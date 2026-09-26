"""可本地复现的配置（TTL、用户资料）。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    access_ttl: float = 300.0  # 访问凭证有效期（秒）
    refresh_ttl: float = 3600.0  # 续期凭证有效期（秒）
    session_ttl: float = 86400.0  # 会话绝对有效期上限（秒）
    seed_users: bool = True  # 是否载入内置演示用户


DEFAULT_SETTINGS = Settings()
