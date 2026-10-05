"""Core type definitions for the session guard."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class DenyReason(str, enum.Enum):
    """Machine-readable, distinguishable reasons for a denied request."""

    INVALID_CREDENTIALS = "invalid_credentials"  # login failed (user/pass/disabled, indistinguishable)
    MISSING_SESSION = "missing_session"
    SESSION_EXPIRED = "session_expired"
    SESSION_REVOKED = "session_revoked"
    REFRESH_REUSED = "refresh_reused"
    FORBIDDEN = "forbidden"  # authenticated but lacks required permission
    ACCOUNT_DISABLED = "account_disabled"  # account disabled in the backend after login
    SESSION_EVICTED = "session_evicted"  # session dropped by the per-user active-session cap
    SESSION_NOT_FOUND = "session_not_found"  # listing/logout target missing or owned by someone else


@dataclass(frozen=True)
class User:
    username: str
    password_hash: str
    disabled: bool = False
    permissions: frozenset[str] = field(default_factory=frozenset)


@dataclass
class Session:
    session_id: str
    username: str
    access_token: str
    refresh_token: str
    access_expires_at: float
    refresh_expires_at: float
    source: str = ""  # client/device identifier supplied at login
    issued_at: float = 0.0  # original login time, preserved across rotation
    refresh_used: bool = False
    revoked: bool = False
    evicted: bool = False  # dropped by the per-user active-session cap
    revoke_reason: str | None = None


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: float
    refresh_expires_at: float
    session_id: str
