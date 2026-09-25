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
    refresh_used: bool = False
    revoked: bool = False
    revoke_reason: str | None = None


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: float
    refresh_expires_at: float
    session_id: str
