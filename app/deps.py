"""FastAPI 依赖：服务定位、请求标识、Bearer 凭证解析与角色守卫。"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from fastapi.security.utils import get_authorization_scheme_param

from app.auth import AuthService
from app.errors import SESSION_MISSING, AuthError
from app.models import AccessDecision

# 拒绝码 -> HTTP 状态码（集中映射，保持判定结果与传输层解耦）
_STATUS_BY_CODE = {
    "session_missing": 401,
    "session_invalid": 401,
    "session_revoked": 401,
    "session_expired": 401,
    "refresh_invalid": 401,
    "invalid_credentials": 401,
    "account_disabled": 403,
    "permission_denied": 403,
}


def status_for(code: str) -> int:
    return _STATUS_BY_CODE.get(code, 403)


@dataclass(frozen=True)
class GuardContext:
    """守卫通过后的请求上下文。"""

    auth: AuthService
    decision: AccessDecision


def get_request_id(request: Request) -> str:
    # 纯 ASGI 中间件运行时 scope["state"] 尚未建立，直接读取 contextvar。
    from app.logging_setup import request_id_var

    return request_id_var.get()


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service  # type: ignore[no-any-return]


def _extract_bearer(request: Request) -> str | None:
    authorization = request.headers.get("Authorization")
    if not authorization:
        return None
    scheme, param = get_authorization_scheme_param(authorization)
    if scheme.lower() != "bearer" or not param:
        return None
    return param


def require_role(required_role: str):
    """生成一个依赖：判定失败抛 AuthError，成功返回 GuardContext。"""

    def dependency(request: Request) -> GuardContext:
        auth = get_auth_service(request)
        access_token = _extract_bearer(request)
        if access_token is None and request.headers.get("Authorization"):
            # 头存在但格式非法，按缺失处理，仍可区分于会话吊销/过期。
            raise AuthError(SESSION_MISSING, 401, "missing bearer credentials")
        decision = auth.authorize(access_token, required_role)
        if not decision.allowed:
            raise AuthError(decision.code, status_for(decision.code), decision.reason)
        return GuardContext(auth=auth, decision=decision)

    return dependency
