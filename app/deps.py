"""FastAPI dependencies: session resolution and permission checks.

Permission semantics: permissions are evaluated at request time against the
user's *current* record, so a permission change takes effect immediately for
all existing sessions of that user. Session validity (expiry/revocation) is
evaluated against the session itself.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass

from fastapi import HTTPException, Request
from fastapi.security.utils import get_authorization_scheme_param

from app.auth import AuthService
from app.models import DenyReason, Session
from app.store import SessionStore, UserStore

logger = logging.getLogger("session_guard")


@dataclass
class AppContext:
    users: UserStore
    sessions: SessionStore
    auth: AuthService


def get_context(request: Request) -> AppContext:
    return request.app.state.ctx


def _request_id(request: Request) -> str:
    rid = request.headers.get("x-request-id")
    if not rid:
        rid = uuid.uuid4().hex[:12]
        request.state.generated_request_id = rid
    return rid


def _deny(request: Request, status: int, reason: DenyReason, detail: str = ""):
    rid = _request_id(request)
    logger.info(
        "deny request_id=%s path=%s reason=%s detail=%s",
        rid, request.url.path, reason.value, detail,
    )
    raise HTTPException(
        status_code=status,
        detail={"reason": reason.value, "detail": detail, "request_id": rid},
    )


def get_session(request: Request) -> Session:
    ctx = get_context(request)
    rid = _request_id(request)
    auth_header = request.headers.get("authorization")
    scheme, token = get_authorization_scheme_param(auth_header or "")
    if not token or scheme.lower() != "bearer":
        _deny(request, 401, DenyReason.MISSING_SESSION, "no bearer token")
    session = ctx.sessions.get_by_access_token(token)
    if session is None:
        _deny(request, 401, DenyReason.SESSION_REVOKED, "unknown or rotated token")
    now = time.time()
    if session.revoked:
        _deny(request, 401, DenyReason.SESSION_REVOKED, session.revoke_reason or "")
    if now >= session.access_expires_at:
        _deny(request, 401, DenyReason.SESSION_EXPIRED, "access token expired")
    logger.info("allow request_id=%s path=%s user=%s", rid, request.url.path, session.username)
    return session


def require_permission(permission: str):
    from fastapi import Depends

    def _check(request: Request, session: Session = Depends(get_session)) -> Session:
        ctx = get_context(request)
        user = ctx.users.get(session.username)
        perms = user.permissions if user else frozenset()
        if permission not in perms:
            _deny(
                request, 403, DenyReason.FORBIDDEN,
                f"user={session.username} lacks permission={permission}",
            )
        return session

    return _check
