"""Authentication and session lifecycle service.

Rules implemented here:
- login: unknown user / wrong password / disabled account all fail with the
  same reason (INVALID_CREDENTIALS) so account existence is not leaked.
- refresh: a refresh token is single-use. Reusing any refresh token (an old
  rotated one, or the current one consumed by a concurrent request) revokes
  the whole session deterministically.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from app.models import DenyReason, Session, TokenPair
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
    ) -> None:
        self._users = users
        self._sessions = sessions
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl

    # -- login -------------------------------------------------------------

    def login(self, username: str, password: str) -> TokenPair:
        user = self._users.get(username)
        # Always run a password verification to keep timing uniform.
        ok = verify_password(password, user.password_hash if user else _DUMMY_HASH)
        if user is None or user.disabled or not ok:
            raise AuthError(DenyReason.INVALID_CREDENTIALS)
        return self._issue_session(username)

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
                raise AuthError(DenyReason.SESSION_REVOKED)
            if now >= session.refresh_expires_at:
                raise AuthError(DenyReason.SESSION_EXPIRED)
            if session.refresh_used:
                # Concurrent second use of the same current token.
                self._revoke(session, DenyReason.REFRESH_REUSED)
                raise AuthError(DenyReason.REFRESH_REUSED)
            session.refresh_used = True
            self._sessions.mark_refresh_used(refresh_token, session.session_id)
            return self._rotate(session, now)

    # -- helpers -----------------------------------------------------------

    def _issue_session(self, username: str) -> TokenPair:
        now = time.time()
        session = Session(
            session_id=secrets.token_urlsafe(16),
            username=username,
            access_token=secrets.token_urlsafe(32),
            refresh_token=secrets.token_urlsafe(32),
            access_expires_at=now + self._access_ttl,
            refresh_expires_at=now + self._refresh_ttl,
        )
        self._sessions.save(session)
        return self._to_pair(session)

    def _rotate(self, session: Session, now: float) -> TokenPair:
        # Replace (not mutate) the session so the store can drop the old
        # token indexes for this session_id.
        rotated = Session(
            session_id=session.session_id,
            username=session.username,
            access_token=secrets.token_urlsafe(32),
            refresh_token=secrets.token_urlsafe(32),
            access_expires_at=now + self._access_ttl,
            refresh_expires_at=now + self._refresh_ttl,
        )
        self._sessions.save(rotated)
        return self._to_pair(rotated)

    def _revoke(self, session: Session, reason: DenyReason) -> None:
        session.revoked = True
        session.revoke_reason = reason.value

    @staticmethod
    def _to_pair(session: Session) -> TokenPair:
        return TokenPair(
            access_token=session.access_token,
            refresh_token=session.refresh_token,
            access_expires_at=session.access_expires_at,
            refresh_expires_at=session.refresh_expires_at,
            session_id=session.session_id,
        )
