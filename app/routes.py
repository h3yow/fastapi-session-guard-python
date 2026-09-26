"""HTTP 路由：登录、续期、登出、受保护资源与本地用户管理。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.deps import GuardContext, get_auth_service, get_request_id, require_role
from app.errors import SESSION_INVALID, USER_NOT_FOUND, AuthError
from app.schemas import (
    LoginRequest,
    RefreshRequest,
    RolesRequest,
    TokenResponse,
)

router = APIRouter()


def _token_response(pair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        session_id=pair.session_id,
        access_expires_at=pair.access_expires_at,
        refresh_expires_at=pair.refresh_expires_at,
        expires_at=pair.expires_at,
    )


@router.post("/auth/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    request_id: str = Depends(get_request_id),
) -> TokenResponse:
    auth = get_auth_service(request)
    # 账号不存在 / 已禁用 / 口令错误在此统一抛出同一错误，对外不可区分。
    pair = auth.login(payload.username, payload.password)
    return _token_response(pair)


@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    request_id: str = Depends(get_request_id),
) -> TokenResponse:
    auth = get_auth_service(request)
    pair = auth.refresh(payload.refresh_token)
    return _token_response(pair)


@router.post("/auth/logout")
async def logout(
    request: Request,
    request_id: str = Depends(get_request_id),
) -> dict:
    auth = get_auth_service(request)
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    else:
        raise AuthError(SESSION_INVALID, 401, "access token not recognized")
    session_id = auth.logout(token)
    return {"revoked": True, "session_id": session_id, "request_id": request_id}


def _whoami(ctx: GuardContext, request_id: str) -> dict:
    user = ctx.decision.user
    return {
        "username": user.username,
        "roles": sorted(user.roles),
        "profile_version": user.version,
        "session_id": ctx.decision.session_id,
        "request_id": request_id,
    }


@router.get("/protected/whoami")
async def whoami(
    request_id: str = Depends(get_request_id),
    ctx: GuardContext = Depends(require_role("view")),
) -> dict:
    # 任意持有 view 角色的会话可访问；响应回显最新资料版本。
    return _whoami(ctx, request_id)


@router.get("/protected/view")
async def view_only(
    request_id: str = Depends(get_request_id),
    ctx: GuardContext = Depends(require_role("view")),
) -> dict:
    return {"resource": "view-data", **_whoami(ctx, request_id)}


@router.get("/protected/admin")
async def admin_only(
    request_id: str = Depends(get_request_id),
    ctx: GuardContext = Depends(require_role("admin")),
) -> dict:
    return {"resource": "admin-data", **_whoami(ctx, request_id)}


# ---------------- 本地用户管理（需 admin 角色） ----------------


def _require_target_user(auth, username: str):
    user = auth.users.get_user(username)
    if user is None:
        raise AuthError(USER_NOT_FOUND, 404, "user not found")
    return user


@router.post("/admin/users/{username}/roles")
async def set_roles(
    username: str,
    payload: RolesRequest,
    request: Request,
    request_id: str = Depends(get_request_id),
    ctx: GuardContext = Depends(require_role("admin")),
) -> dict:
    auth = get_auth_service(request)
    _require_target_user(auth, username)
    auth.users.set_roles(username, set(payload.roles))
    user = auth.users.get_user(username)
    return {
        "username": username,
        "roles": sorted(user.roles),
        "profile_version": user.version,
        "request_id": request_id,
    }


@router.post("/admin/users/{username}/disable")
async def disable_user(
    username: str,
    request: Request,
    request_id: str = Depends(get_request_id),
    ctx: GuardContext = Depends(require_role("admin")),
) -> dict:
    auth = get_auth_service(request)
    _require_target_user(auth, username)
    auth.users.set_disabled(username, True)
    return {"username": username, "disabled": True, "request_id": request_id}


@router.post("/admin/users/{username}/enable")
async def enable_user(
    username: str,
    request: Request,
    request_id: str = Depends(get_request_id),
    ctx: GuardContext = Depends(require_role("admin")),
) -> dict:
    auth = get_auth_service(request)
    _require_target_user(auth, username)
    auth.users.set_disabled(username, False)
    return {"username": username, "disabled": False, "request_id": request_id}
