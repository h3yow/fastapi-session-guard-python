"""领域模型：用户、会话、判定结果。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class User:
    """本地用户资料（权限判定始终读取最新资料）。"""

    username: str
    password_hash: str
    roles: set[str] = field(default_factory=set)
    disabled: bool = False
    version: int = 0


@dataclass
class Session:
    """一次登录产生的会话。"""

    session_id: str
    username: str
    created_at: float
    expires_at: float  # 会话（续期窗口）绝对过期时间
    refresh_token_hash: str  # 当前一代续期凭证的哈希（单代有效）
    refresh_expires_at: float  # 当前续期凭证过期时间
    used_refresh_hashes: set[str] = field(default_factory=set)  # 历代续期凭证哈希（重放识别）
    revoked: bool = False
    revoke_reason: str | None = None


@dataclass(frozen=True)
class AccessTokenInfo:
    """访问凭证在服务端的登记信息。"""

    session_id: str
    expires_at: float


@dataclass(frozen=True)
class TokenPair:
    """登录/续期成功后对外签发的凭证对。"""

    access_token: str
    refresh_token: str
    session_id: str
    access_expires_at: float
    refresh_expires_at: float
    expires_at: float


@dataclass(frozen=True)
class AccessDecision:
    """受保护接口的可解释判定结果。"""

    allowed: bool
    code: str
    reason: str
    user: User | None = None
    session_id: str | None = None
