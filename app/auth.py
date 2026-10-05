"""Authentication and session lifecycle service.

Rules implemented here:
- login: unknown user / wrong password / disabled account all fail with the
  same reason (INVALID_CREDENTIALS) so account existence is not leaked.
- refresh: a refresh token is single-use. Reusing any refresh token (an old
  rotated one, or the current one consumed by a concurrent request) revokes
  the whole session deterministically.
- multi-session: one account may hold up to ``max_sessions`` active sessions.
  Issuing beyond the cap evicts the *oldest* session (lowest issued_seq)
  with reason SESSION_EVICTED; the just-issued session is never evicted.
- logout: revoking a session and an in-flight refresh of the same session
  are serialized by the store lock, so exactly one deterministic outcome
  results; after logout no refresh of that session can ever succeed again.
- account state: a disabled account's existing sessions fail at request
  time (checked live, not cached) and recover when the account is re-enabled.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import secrets
import time

from app.models import DenyReason, Session, SessionInfo, TokenPair
from app.store import SessionStore, UserStore

_PBKDF2_ITERATIONS = 60_000
_DUMMY_HASH = ""  # set at module import to equalize timing for unknown users


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    ).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    salt, _, _ = stored.partition("$")
    return hmac.compare_digest(hash_password(password, salt), stored)


_DUMMY_HASH = hash_password("dummy-password-for-timing")


class AuthError(Exception):
    def __init__(self, reason: DenyReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class AuthService:
    def __init__(
        self,
        users: UserStore,
        sessions: SessionStore,
        access_ttl: float = 300.0,
        refresh_ttl: float = 3600.0,
        max_sessions: int = 5,
    ) -> None:
        self._users = users
        self._sessions = sessions
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._max_sessions = max_sessions
        self._seq = itertools.count(1)

    # -- login -------------------------------------------------------------

    def login(self, username: str, password: str, source: str = "") -> TokenPair:
        user = self._users.get(username)
        # Always run a password verification to keep timing uniform.
        ok = verify_password(password, user.password_hash if user else _DUMMY_HASH)
        if user is None or user.disabled or not ok:
            raise AuthError(DenyReason.INVALID_CREDENTIALS)
        return self._issue_session(username, source)

    # -- refresh -----------------------------------------------------------

    def refresh(self, refresh_token: str) -> TokenPair:
        now = time.time()
        with self._sessions.transaction():
            session = self._sessions.get_by_refresh_token(refresh_token)
            if session is None:
                # Not a live token: maybe a rotated-out one being replayed.
                victim = self._sessions.get_session_for_used_refresh(refresh_token)
                if victim is not None:
                    self._revoke(victim, DenyReason.REFRESH_REUSED)
                raise AuthError(DenyReason.REFRESH_REUSED)
            if session.revoked:
                if session.revoke_reason == DenyReason.SESSION_EVICTED.value:
                    raise AuthError(DenyReason.SESSION_EVICTED)
                raise AuthError(DenyReason.SESSION_REVOKED)
            if now >= session.refresh_expires_at:
                raise AuthError(DenyReason.SESSION_EXPIRED)
            self._check_account_enabled(session.username)
            if session.refresh_used:
                # Concurrent second use of the same current token.
                self._revoke(session, DenyReason.REFRESH_REUSED)
                raise AuthError(DenyReason.REFRESH_REUSED)
            session.refresh_used = True
            self._sessions.mark_refresh_used(refresh_token, session.session_id)
            return self._rotate(session, now)

    # -- session management --------------------------------------------------

    def list_sessions(self, username: str) -> list[SessionInfo]:
        """The account's still-valid sessions, oldest first."""
        now = time.time()
        with self._sessions.transaction():
            return [
                self._to_info(s)
                for s in self._sessions.list_by_user(username)
                if self._is_active(s, now)
            ]

    def logout(self, username: str, session_id: str) -> None:
        """Revoke one session owned by ``username``.

        Unknown ids and sessions owned by someone else are
        indistinguishable: both fail with SESSION_NOT_FOUND.
        """
        with self._sessions.transaction():
            session = self._sessions.get(session_id)
            if session is None or session.username != username:
                raise AuthError(DenyReason.SESSION_NOT_FOUND)
            self._revoke(session, DenyReason.SESSION_REVOKED)

    def logout_all(self, username: str) -> int:
        """Revoke every session of the account; returns how many were live."""
        now = time.time()
        with self._sessions.transaction():
            count = 0
            for session in self._sessions.list_by_user(username):
                if self._is_active(session, now):
                    self._revoke(session, DenyReason.SESSION_REVOKED)
                    count += 1
            return count

    # -- helpers -----------------------------------------------------------

    def _issue_session(self, username: str, source: str) -> TokenPair:
        now = time.time()
        with self._sessions.transaction():
            session = Session(
                session_id=secrets.token_urlsafe(16),
                username=username,
                access_token=secrets.token_urlsafe(32),
                refresh_token=secrets.token_urlsafe(32),
                access_expires_at=now + self._access_ttl,
                refresh_expires_at=now + self._refresh_ttl,
                source=source,
                issued_at=now,
                issued_seq=next(self._seq),
            )
            self._sessions.save(session)
            self._enforce_cap(username, now)
        return self._to_pair(session)

    def _enforce_cap(self, username: str, now: float) -> None:
        """Evict the oldest active sessions beyond the per-account cap.

        Caller must hold the store lock. ``list_by_user`` returns sessions
        ordered by issued_seq, so the head of the list is the oldest; the
        just-issued session has the highest seq and is never evicted here.
        """
        active = [
            s for s in self._sessions.list_by_user(username)
            if self._is_active(s, now)
        ]
        for victim in active[: max(0, len(active) - self._max_sessions)]:
            self._revoke(victim, DenyReason.SESSION_EVICTED)

    def _check_account_enabled(self, username: str) -> None:
        user = self._users.get(username)
        if user is None or user.disabled:
            raise AuthError(DenyReason.ACCOUNT_DISABLED)

    @staticmethod
    def _is_active(session: Session, now: float) -> bool:
        return not session.revoked and now < session.refresh_expires_at

    def _rotate(self, session: Session, now: float) -> TokenPair:
        # Replace (not mutate) the session so the store can drop the old
        # token indexes for this session_id. Identity fields (source,
        # issued_at, issued_seq) carry over so rotation is not a new session.
        rotated = Session(
            session_id=session.session_id,
            username=session.username,
            access_token=secrets.token_urlsafe(32),
            refresh_token=secrets.token_urlsafe(32),
            access_expires_at=now + self._access_ttl,
            refresh_expires_at=now + self._refresh_ttl,
            source=session.source,
            issued_at=session.issued_at,
            issued_seq=session.issued_seq,
        )
        self._sessions.save(rotated)
        return self._to_pair(rotated)

    def _revoke(self, session: Session, reason: DenyReason) -> None:
        session.revoked = True
        session.revoke_reason = reason.value

    @staticmethod
    def _to_info(session: Session) -> SessionInfo:
        return SessionInfo(
            session_id=session.session_id,
            source=session.source,
            issued_at=session.issued_at,
            access_expires_at=session.access_expires_at,
            refresh_expires_at=session.refresh_expires_at,
        )

    @staticmethod
    def _to_pair(session: Session) -> TokenPair:
        return TokenPair(
            access_token=session.access_token,
            refresh_token=session.refresh_token,
            access_expires_at=session.access_expires_at,
            refresh_expires_at=session.refresh_expires_at,
            session_id=session.session_id,
        )
