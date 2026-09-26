"""内置本地演示用户资料（仅用于本地复现，可在文档中查到口令）。"""

from __future__ import annotations

from app.models import User
from app.security import hash_password
from app.store import UserStore

# 角色约定：view 为普通访问，admin 为管理员访问。
_DEMO_USERS = (
    ("alice", "alice-pass-123", {"view", "admin"}, False),
    ("bob", "bob-pass-123", {"view"}, False),
    ("carol", "carol-pass-123", {"view"}, True),  # 被禁用账号
)


def seed_users(users: UserStore) -> None:
    for username, password, roles, disabled in _DEMO_USERS:
        users.add_user(
            User(
                username=username,
                password_hash=hash_password(password),
                roles=set(roles),
                disabled=disabled,
            )
        )
