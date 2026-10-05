"""Authentication and session lifecycle service.

Rules implemented here:
- login: unknown user / wrong password / disabled account all fail with the
  same reason (INVALID_CREDENTIALS) so account existence is not leaked.
  A successful login creates an independent session tagged with a client
  ``source``; per-user active sessions are capped and overflow is evicted
  deterministically (oldest issued_at, session_id as tie-break).
- refresh: a refresh token is single-use. Reusing any refresh token (an old
  rotated one, or the current one consumed by a concurrent request) revokes
  the whole session deterministically.
- logout: single-session or logout-all take effect immediately under the
  store lock; a racing refresh can never succeed after logout commits.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time

from app.models import DenyReason, Session, TokenPair
from app.store import SessionStore, UserStore

logger = logging.getLogger("session_guard")

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
        max_sessions_per_user: int = 5,
    ) -> None:
        self._users = users
        self._sessions = sessions
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._max_sessions = max_sessions_per_user

    # -- login -------------------------------------------------------------

    def login(self, username: str, password: str, source: str = "") -> TokenPair:
        user = self._users.get(username)
        # Always run a password verification to keep timing uniform.
        ok = verify_password(password, user.password_hash if user else _DUMMY_HASH)
        if user is None or user.disabled or not ok:
            raise AuthError(DenyReason.INVALID_CREDENTIALS)
        return self._issue_session(username, source)

    # -- session listing / logout -----------------------------------------

    def list_sessions(self, username: str) -> list[Session]:
        """The user's currently active sessions (youngest first)."""
        now = time.time()
        with self._sessions.transaction():
            active = self._sessions.active_for_user(username, now)
        active.sort(key=lambda s: (s.issued_at, s.session_id))
        return active

    def logout(self, username: str, session_id: str) -> None:
        """Revoke one session. A missing/foreign/inactive target raises
        SESSION_NOT_FOUND so callers cannot probe other users' sessions."""
        with self._sessions.transaction():
            session = self._sessions.get(session_id)
            now = time.time()
            if (
                session is None
                or session.username != username
                or session.revoked
                or session.evicted
                or now >= session.refresh_expires_at
            ):
                raise AuthError(DenyReason.SESSION_NOT_FOUND)
            self._mark_revoked(session, DenyReason.SESSION_REVOKED, "user logout")

    def logout_all(self, username: str) -> int:
        """Revoke every active session of the user. Sessions of other users
        are never touched. Returns the number of sessions revoked."""
        now = time.time()
        count = 0
        with self._sessions.transaction():
            for session in self._sessions.active_for_user(username, now):
                self._mark_revoked(session, DenyReason.SESSION_REVOKED, "user logout-all")
                count += 1
        logger.info("logout_all user=%s revoked=%d", username, count)
        return count

    # -- refresh -----------------------------------------------------------

    def refresh(self, refresh_token: str) -> TokenPair:
        now = time.time()
        with self._sessions.transaction():
            session = self._sessions.get_by_refresh_token(refresh_token)
            if session is None:
                # Not a live token: maybe a rotated-out one being replayed.
                victim = self._sessions.get_session_for_used_refresh(refresh_token)
                if victim is not None:
                    self._mark_revoked(victim, DenyReason.REFRESH_REUSED, "refresh replay")
                raise AuthError(DenyReason.REFRESH_REUSED)
            if session.evicted:
                raise AuthError(DenyReason.SESSION_EVICTED)
            if session.revoked:
                raise AuthError(DenyReason.SESSION_REVOKED)
            if now >= session.refresh_expires_at:
                raise AuthError(DenyReason.SESSION_EXPIRED)
            # Backend account state is evaluated live: disabling an account
            # blocks refresh of all its existing sessions immediately.
            user = self._users.get(session.username)
            if user is None or user.disabled:
                raise AuthError(DenyReason.ACCOUNT_DISABLED)
            if session.refresh_used:
                # Concurrent second use of the same current token.
                self._mark_revoked(session, DenyReason.REFRESH_REUSED, "concurrent refresh reuse")
                raise AuthError(DenyReason.REFRESH_REUSED)
            session.refresh_used = True
            self._sessions.mark_refresh_used(refresh_token, session.session_id)
            return self._rotate(session, now)

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
            )
            self._sessions.save(session)
            self._enforce_cap(username, now)
        return self._to_pair(session)

    def _enforce_cap(self, username: str, now: float) -> None:
        """Evict oldest active sessions while the user is over the cap.

        Ordering: earliest ``issued_at`` wins eviction; ties (identical
        issuance time) break deterministically by smallest ``session_id``.
        Expired sessions don't count toward the cap and are never evicted.
        Must be called while holding the store transaction lock.
        """
        active = self._sessions.active_for_user(username, now)
        excess = len(active) - self._max_sessions
        if excess <= 0:
            return
        active.sort(key=lambda s: (s.issued_at, s.session_id))
        for victim in active[:excess]:
            victim.evicted = True
            victim.revoke_reason = DenyReason.SESSION_EVICTED.value
            logger.info(
                "evict user=%s session_id=%s issued_at=%s reason=session_evicted "
                "active=%d cap=%d",
                username, victim.session_id, victim.issued_at,
                len(active), self._max_sessions,
            )

    def _rotate(self, session: Session, now: float) -> TokenPair:
        # Replace (not mutate) the session so the store can drop the old
        # token indexes for this session_id. Source and original issuance
        # time are preserved; eviction order is therefore stable across
        # refreshes.
        rotated = Session(
            session_id=session.session_id,
            username=session.username,
            access_token=secrets.token_urlsafe(32),
            refresh_token=secrets.token_urlsafe(32),
            access_expires_at=now + self._access_ttl,
            refresh_expires_at=now + self._refresh_ttl,
            source=session.source,
            issued_at=session.issued_at,
        )
        self._sessions.save(rotated)
        return self._to_pair(rotated)

    def _mark_revoked(self, session: Session, reason: DenyReason, detail: str) -> None:
        # An earlier terminal state (e.g. eviction) is never overwritten, so
        # every later request keeps getting the stable, original reason.
        if session.revoked or session.evicted:
            return
        session.revoked = True
        session.revoke_reason = reason.value
        logger.info(
            "revoke user=%s session_id=%s reason=%s detail=%s",
            session.username, session.session_id, reason.value, detail,
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
