"""内存存储：用户资料、会话与访问凭证登记。

所有会话变更方法在同一把 RLock 下串行化，保证并发续期/重放判定的确定性：
无论多少请求并发，同一把锁保证「比对旧凭证 → 换发新凭证 → 登记旧凭证」
作为一个原子步骤发生，第二个到达者只能看到换发后的状态。
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from app.models import AccessTokenInfo, Session, User
from app.security import hash_token


class UserStore:
    """本地用户资料。权限判定每次都读取这里的最新资料。"""

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._lock = threading.RLock()

    def add_user(self, user: User) -> None:
        with self._lock:
            self._users[user.username] = user

    def get_user(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username)

    def set_roles(self, username: str, roles: set[str]) -> None:
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise KeyError(username)
            user.roles = set(roles)
            user.version += 1

    def set_disabled(self, username: str, disabled: bool) -> None:
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise KeyError(username)
            user.disabled = disabled
            user.version += 1


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, Session] = {}
        self._access_tokens: dict[str, AccessTokenInfo] = {}
        # 每一代（含已轮换的旧代）续期凭证哈希 -> 会话 ID
        self._refresh_index: dict[str, str] = {}

    @contextmanager
    def lock(self) -> Iterator[None]:
        """暴露存储锁，供服务层把「检查+换发」包成原子步骤。"""
        with self._lock:
            yield

    def create_session(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.session_id] = session
            self._refresh_index[session.refresh_token_hash] = session.session_id

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def find_by_refresh_hash(self, refresh_hash: str) -> Session | None:
        with self._lock:
            session_id = self._refresh_index.get(refresh_hash)
            if session_id is None:
                return None
            return self._sessions.get(session_id)

    def get_access_token(self, token: str) -> AccessTokenInfo | None:
        with self._lock:
            return self._access_tokens.get(hash_token(token))

    def put_access_token(self, token: str, info: AccessTokenInfo) -> None:
        with self._lock:
            self._access_tokens[hash_token(token)] = info

    def rotate_refresh(
        self,
        session: Session,
        new_refresh_hash: str,
        refresh_expires_at: float,
    ) -> None:
        """换发新一代续期凭证（调用方必须持有 lock）。

        旧哈希保留在索引中：此后再出现旧凭证即可被识别为重放。
        """
        with self._lock:
            session.used_refresh_hashes.add(session.refresh_token_hash)
            session.refresh_token_hash = new_refresh_hash
            session.refresh_expires_at = refresh_expires_at
            session.used_refresh_hashes.add(new_refresh_hash)
            self._refresh_index[new_refresh_hash] = session.session_id

    def revoke_session(self, session_id: str, reason: str) -> None:
        """使整个会话失效（保留凭证索引，统一返回 session_revoked）。

        会话上的 revoked 标记会拦截其名下所有访问/续期凭证；续期凭证哈希
        索引也保留：吊销后再出示旧凭证仍能稳定判定为 session_revoked，
        而不是无法区分的 session_invalid。
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return
            session.revoked = True
            session.revoke_reason = reason
