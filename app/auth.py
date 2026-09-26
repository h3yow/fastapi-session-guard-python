"""认证与续期核心逻辑（所有判定规则集中于此，便于审计与测试）。

续期重放/并发的确定性规则：
  * 同一把存储锁内完成「比对当前续期凭证 → 换发新一代 → 旧凭证登记」；
  * 一张续期凭证（按哈希）在整个会话生命周期内最多成功使用一次；
  * 凡出示已轮换掉的旧凭证（并发争抢失败或事后重放），立即吊销整个会话；
  * 因此并发两次使用同一凭证时，恰有一次成功，随后整个会话（含刚换发的
    新凭证）失效；按顺序正常续期不受影响。

权限变更语义：
  * 访问判定每次实时读取本地用户资料（角色、禁用状态、版本号），
    不把权限快照进会话；权限或禁用状态变更对下一次请求立即生效。
"""

from __future__ import annotations

import secrets

from app.clock import TimeSource
from app.config import Settings
from app.errors import (
    ACCOUNT_DISABLED,
    LOGIN_INVALID,
    PERMISSION_DENIED,
    REFRESH_INVALID,
    SESSION_EXPIRED,
    SESSION_INVALID,
    SESSION_MISSING,
    SESSION_REVOKED,
    AuthError,
)
from app.logging_setup import get_logger
from app.models import AccessDecision, AccessTokenInfo, Session, TokenPair
from app.security import (
    constant_time_equals,
    generate_token,
    hash_token,
    verify_password,
)
from app.store import SessionStore, UserStore

# 与任意真实哈希结构一致的哑哈希，用于账号不存在时消耗相近的校验时间。
_DUMMY_HASH = "pbkdf2_sha256$200000$" + "00" * 16 + "$" + "00" * 32

log = get_logger()


def _deny(code: str, reason: str, session_id: str | None = None) -> AccessDecision:
    return AccessDecision(allowed=False, code=code, reason=reason, session_id=session_id)


class AuthService:
    def __init__(
        self,
        users: UserStore,
        sessions: SessionStore,
        settings: Settings,
        time_fn: TimeSource,
    ) -> None:
        self.users = users
        self.sessions = sessions
        self.settings = settings
        self.time = time_fn

    # ---------------- 登录 ----------------

    def login(self, username: str, password: str) -> TokenPair:
        """验证本地资料并签发新会话。三类失败对外完全不可区分。"""
        user = self.users.get_user(username)
        if user is None:
            # 账号不存在：仍执行一次完整口令推导，避免通过耗时差异探测账号。
            verify_password(password, _DUMMY_HASH)
            log.info(
                "auth decision: login rejected code=%s reason=unknown_or_disabled_or_bad_password",
                LOGIN_INVALID,
            )
            raise AuthError(
                LOGIN_INVALID,
                401,
                "invalid credentials",
            )

        password_ok = verify_password(password, user.password_hash)
        # 账号不存在 / 被禁用 / 口令错误使用同一错误码与同一文案。
        if user.disabled or not password_ok:
            log.info(
                "auth decision: login rejected code=%s reason=bad_or_disabled_or_unknown user=%s",
                LOGIN_INVALID,
                user.username,
            )
            raise AuthError(LOGIN_INVALID, 401, "invalid credentials")

        tokens = self._issue_tokens(
            session_id=secrets.token_urlsafe(18),
            username=user.username,
            now=self.time(),
        )
        log.info(
            "auth decision: login allowed user=%s session_id=%s",
            user.username,
            tokens.session_id,
        )
        return tokens

    # ---------------- 续期 ----------------

    def refresh(self, refresh_token: str) -> TokenPair:
        """用续期凭证换发新凭证对；重放/并发复用触发整体吊销。"""
        if not refresh_token:
            raise AuthError(REFRESH_INVALID, 401, "refresh token required")

        presented = hash_token(refresh_token)
        now = self.time()

        with self.sessions.lock():
            session = self.sessions.find_by_refresh_hash(presented)

            if session is None:
                # 从未签发过的凭证：不泄露任何会话信息。
                log.info(
                    "auth decision: refresh rejected code=%s reason=token_not_recognized",
                    REFRESH_INVALID,
                )
                raise AuthError(REFRESH_INVALID, 401, "refresh token not recognized")

            if session.revoked:
                log.info(
                    "auth decision: refresh rejected code=%s session_id=%s reason=%s",
                    SESSION_REVOKED,
                    session.session_id,
                    session.revoke_reason or "revoked",
                )
                raise AuthError(SESSION_REVOKED, 401, "session has been revoked")

            if now >= session.expires_at:
                log.info(
                    "auth decision: refresh rejected code=%s session_id=%s reason=lifetime_expired",
                    SESSION_EXPIRED,
                    session.session_id,
                )
                raise AuthError(SESSION_EXPIRED, 401, "session expired")

            current = session.refresh_token_hash
            if constant_time_equals(presented, current):
                if now >= session.refresh_expires_at:
                    log.info(
                        "auth decision: refresh rejected code=%s session_id=%s reason=refresh_ttl",
                        SESSION_EXPIRED,
                        session.session_id,
                    )
                    raise AuthError(SESSION_EXPIRED, 401, "refresh token expired")

                # 唯一的正常路径：旧凭证立即作废，换发新一代。
                pair = self._rotate(session, now)
                log.info(
                    "auth decision: refresh allowed session_id=%s reason=current_credential",
                    session.session_id,
                )
                return pair

            if presented in session.used_refresh_hashes:
                # 旧凭证再次出现：并发争抢失败或事后重放，按确定规则整体吊销。
                self.sessions.revoke_session(session.session_id, "refresh_token_replay")
                log.warning(
                    "refresh decision rejected code=%s session=%s "
                    "reason=refresh_token_replay whole_session_revoked=true",
                    SESSION_REVOKED,
                    session.session_id,
                )
                raise AuthError(
                    SESSION_REVOKED,
                    401,
                    "refresh token replay detected; session revoked",
                )

            log.info(
                "auth decision: refresh rejected code=%s session_id=%s reason=generation_mismatch",
                REFRESH_INVALID,
                session.session_id,
            )
            raise AuthError(REFRESH_INVALID, 401, "refresh token not recognized")

    # ---------------- 访问控制 ----------------

    def authorize(self, access_token: str | None, required_role: str) -> AccessDecision:
        """对受保护资源做可解释判定，返回可区分的拒绝码（不抛业务异常）。"""
        if not access_token:
            decision = _deny(SESSION_MISSING, "no access token presented")
            log.info("auth decision: access rejected code=%s", decision.code)
            return decision

        info = self.sessions.get_access_token(access_token)
        if info is None:
            decision = _deny(
                SESSION_INVALID,
                "access token not recognized or revoked with session",
            )
            log.info("auth decision: access rejected code=%s", decision.code)
            return decision

        session = self.sessions.get_session(info.session_id)
        if session is None:
            decision = _deny(SESSION_INVALID, "session not found", info.session_id)
            log.info("auth decision: access rejected code=%s", decision.code)
            return decision

        if session.revoked:
            decision = _deny(
                SESSION_REVOKED,
                f"session revoked: {session.revoke_reason or 'unknown'}",
                session.session_id,
            )
            log.info(
                "auth decision: access rejected code=%s session_id=%s reason=%s",
                decision.code,
                session.session_id,
                session.revoke_reason,
            )
            return decision

        now = self.time()
        if now >= session.expires_at:
            decision = _deny(SESSION_EXPIRED, "session lifetime expired", session.session_id)
            log.info(
                "auth decision: access rejected code=%s session_id=%s",
                decision.code,
                session.session_id,
            )
            return decision

        if now >= info.expires_at:
            decision = _deny(SESSION_EXPIRED, "access token expired", session.session_id)
            log.info(
                "auth decision: access rejected code=%s session_id=%s reason=access_token_expired",
                decision.code,
                session.session_id,
            )
            return decision

        # 实时读取最新用户资料：权限/禁用变更对下一次请求立即生效。
        user = self.users.get_user(session.username)
        if user is None:
            decision = _deny(SESSION_INVALID, "user profile no longer exists", session.session_id)
            log.info(
                "auth decision: access rejected code=%s session_id=%s reason=user_missing",
                decision.code,
                session.session_id,
            )
            return decision

        if user.disabled:
            decision = _deny(ACCOUNT_DISABLED, "account disabled", session.session_id)
            log.info(
                "auth decision: access rejected code=%s session_id=%s user=%s",
                decision.code,
                session.session_id,
                user.username,
            )
            return decision

        if required_role not in user.roles:
            decision = _deny(
                PERMISSION_DENIED,
                f"role '{required_role}' required; roles={sorted(user.roles)} "
                f"(profile_version={user.version})",
                session.session_id,
            )
            decision = AccessDecision(
                allowed=False,
                code=decision.code,
                reason=decision.reason,
                user=user,
                session_id=session.session_id,
            )
            log.info(
                "auth decision: access rejected code=%s session_id=%s user=%s",
                decision.code,
                session.session_id,
                user.username,
            )
            return decision

        decision = AccessDecision(
            allowed=True,
            code="ok",
            reason=f"role '{required_role}' present (profile_version={user.version})",
            user=user,
            session_id=session.session_id,
        )
        log.info(
            "auth decision: access allowed code=ok session_id=%s user=%s role=%s",
            session.session_id,
            user.username,
            required_role,
        )
        return decision

    # ---------------- 登出 ----------------

    def logout(self, access_token: str | None) -> str:
        """主动吊销当前会话；返回会话 ID。"""
        if not access_token:
            raise AuthError(SESSION_MISSING, 401, "no access token presented")
        info = self.sessions.get_access_token(access_token)
        if info is None:
            raise AuthError(SESSION_INVALID, 401, "access token not recognized")
        self.sessions.revoke_session(info.session_id, "user_logout")
        log.info("auth decision: logout session_id=%s reason=user_logout", info.session_id)
        return info.session_id

    # ---------------- 内部工具 ----------------

    def _issue_tokens(self, session_id: str, username: str, now: float) -> TokenPair:
        access_raw = generate_token()
        refresh_raw = generate_token()
        session_expires_at = now + self.settings.session_ttl
        refresh_expires_at = min(now + self.settings.refresh_ttl, session_expires_at)
        access_expires_at = min(now + self.settings.access_ttl, session_expires_at)
        session = Session(
            session_id=session_id,
            username=username,
            created_at=now,
            expires_at=session_expires_at,
            refresh_token_hash=hash_token(refresh_raw),
            refresh_expires_at=refresh_expires_at,
            used_refresh_hashes=set(),
        )
        self.sessions.create_session(session)
        self.sessions.put_access_token(access_raw, AccessTokenInfo(session_id, access_expires_at))
        return TokenPair(
            access_token=access_raw,
            refresh_token=refresh_raw,
            session_id=session_id,
            access_expires_at=access_expires_at,
            refresh_expires_at=refresh_expires_at,
            expires_at=session_expires_at,
        )

    def _rotate(self, session: Session, now: float) -> TokenPair:
        """调用方必须已持有 sessions 锁。"""
        access_raw = generate_token()
        refresh_raw = generate_token()
        refresh_expires_at = min(now + self.settings.refresh_ttl, session.expires_at)
        access_expires_at = min(now + self.settings.access_ttl, session.expires_at)
        self.sessions.rotate_refresh(session, hash_token(refresh_raw), refresh_expires_at)
        self.sessions.put_access_token(
            access_raw, AccessTokenInfo(session.session_id, access_expires_at)
        )
        return TokenPair(
            access_token=access_raw,
            refresh_token=refresh_raw,
            session_id=session.session_id,
            access_expires_at=access_expires_at,
            refresh_expires_at=refresh_expires_at,
            expires_at=session.expires_at,
        )
