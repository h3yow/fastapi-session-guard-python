"""In-memory stores for users and sessions.

All mutating operations are guarded by locks so that concurrent requests
(e.g. parallel refresh attempts) observe a single, deterministic state.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from dataclasses import replace
from typing import Iterator

from app.models import Session, User


class UserStore:
    def __init__(self, users: dict[str, User] | None = None) -> None:
        self._users: dict[str, User] = dict(users or {})
        self._lock = threading.Lock()

    def get(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    def set_permissions(self, username: str, permissions: frozenset[str]) -> None:
        """Replace a user's permissions atomically.

        Sessions are not touched here; how existing sessions observe the
        change is decided by the permission-check layer (see deps.py).
        """
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise KeyError(username)
            self._users[username] = replace(user, permissions=frozenset(permissions))

    def set_disabled(self, username: str, disabled: bool) -> None:
        """Enable/disable an account atomically.

        Existing sessions are not touched: the disabled flag is evaluated at
        request time, so the change takes effect immediately for all of them.
        """
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise KeyError(username)
            self._users[username] = replace(user, disabled=disabled)


class SessionStore:
    def __init__(self) -> None:
        self._by_id: dict[str, Session] = {}
        self._by_access: dict[str, str] = {}
        self._by_refresh: dict[str, str] = {}
        self._by_user: dict[str, set[str]] = {}
        # Rotated-out refresh tokens -> session_id, kept for replay detection.
        self._used_refresh: dict[str, str] = {}
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Hold the store lock across a read-modify-write sequence."""
        with self._lock:
            yield

    def save(self, session: Session) -> None:
        with self._lock:
            old = self._by_id.get(session.session_id)
            if old is not None:
                self._by_access.pop(old.access_token, None)
                self._by_refresh.pop(old.refresh_token, None)
            self._by_id[session.session_id] = session
            self._by_access[session.access_token] = session.session_id
            self._by_refresh[session.refresh_token] = session.session_id
            self._by_user.setdefault(session.username, set()).add(session.session_id)

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            return self._by_id.get(session_id)

    def get_by_access_token(self, token: str) -> Session | None:
        with self._lock:
            sid = self._by_access.get(token)
            return self._by_id.get(sid) if sid else None

    def get_by_refresh_token(self, token: str) -> Session | None:
        with self._lock:
            sid = self._by_refresh.get(token)
            return self._by_id.get(sid) if sid else None

    def mark_refresh_used(self, token: str, session_id: str) -> None:
        """Record a rotated-out refresh token so later reuse is detectable."""
        with self._lock:
            self._used_refresh[token] = session_id

    def get_session_for_used_refresh(self, token: str) -> Session | None:
        with self._lock:
            sid = self._used_refresh.get(token)
            return self._by_id.get(sid) if sid else None

    # -- per-user session management --------------------------------------

    def list_for_user(self, username: str) -> list[Session]:
        """All sessions ever issued to the user (including dead ones).

        Active filtering is applied by the service layer, which decides what
        "active" means while holding the transaction lock.
        """
        with self._lock:
            return [self._by_id[sid] for sid in self._by_user.get(username, set())
                    if sid in self._by_id]

    def active_for_user(self, username: str, now: float) -> list[Session]:
        with self._lock:
            return [
                s for s in self.list_for_user(username)
                if not s.revoked and not s.evicted and now < s.refresh_expires_at
            ]
