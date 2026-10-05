"""HTTP routes: login, refresh, and protected resources."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth import AuthError
from app.deps import AppContext, _request_id, get_context, get_session, require_permission
from app.models import DenyReason, Session, TokenPair

logger = logging.getLogger("session_guard")

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str
    source: str = ""  # optional client/device label, shown in the session list


class RefreshBody(BaseModel):
    refresh_token: str


def _pair_response(pair: TokenPair) -> dict:
    return {
        "session_id": pair.session_id,
        "access_token": pair.access_token,
        "refresh_token": pair.refresh_token,
        "access_expires_at": pair.access_expires_at,
        "refresh_expires_at": pair.refresh_expires_at,
        "token_type": "bearer",
    }


def _auth_error_response(request: Request, err: AuthError) -> HTTPException:
    rid = request.headers.get("x-request-id", "-")
    logger.info(
        "deny request_id=%s path=%s reason=%s", rid, request.url.path, err.reason.value
    )
    return HTTPException(
        status_code=401,
        detail={"reason": err.reason.value, "request_id": rid},
    )


@router.post("/login")
def login(body: LoginBody, request: Request) -> dict:
    ctx: AppContext = get_context(request)
    try:
        pair = ctx.auth.login(body.username, body.password, body.source)
    except AuthError as err:
        raise _auth_error_response(request, err)
    return _pair_response(pair)


@router.post("/refresh")
def refresh(body: RefreshBody, request: Request) -> dict:
    ctx: AppContext = get_context(request)
    try:
        pair = ctx.auth.refresh(body.refresh_token)
    except AuthError as err:
        raise _auth_error_response(request, err)
    return _pair_response(pair)


@router.get("/sessions")
def list_sessions(request: Request, session: Session = Depends(get_session)) -> dict:
    """List the caller's own still-valid sessions (never other accounts')."""
    ctx: AppContext = get_context(request)
    infos = ctx.auth.list_sessions(session.username)
    return {
        "sessions": [
            {
                "session_id": i.session_id,
                "source": i.source,
                "issued_at": i.issued_at,
                "access_expires_at": i.access_expires_at,
                "refresh_expires_at": i.refresh_expires_at,
                "current": i.session_id == session.session_id,
            }
            for i in infos
        ]
    }


@router.delete("/sessions/{session_id}")
def logout_session(
    session_id: str, request: Request, session: Session = Depends(get_session)
) -> dict:
    """Revoke one of the caller's own sessions, effective immediately."""
    ctx: AppContext = get_context(request)
    try:
        ctx.auth.logout(session.username, session_id)
    except AuthError as err:
        # Unknown id and someone else's session are indistinguishable (404).
        rid = request.headers.get("x-request-id", "-")
        logger.info(
            "deny request_id=%s path=%s reason=%s", rid, request.url.path,
            err.reason.value,
        )
        raise HTTPException(
            status_code=404,
            detail={"reason": err.reason.value, "request_id": rid},
        )
    logger.info(
        "logout request_id=%s user=%s session_id=%s",
        _request_id(request), session.username, session_id,
    )
    return {"revoked": session_id}


@router.delete("/sessions")
def logout_all_sessions(request: Request, session: Session = Depends(get_session)) -> dict:
    """Revoke every session of the caller's account, including this one."""
    ctx: AppContext = get_context(request)
    count = ctx.auth.logout_all(session.username)
    logger.info(
        "logout_all request_id=%s user=%s revoked=%d",
        _request_id(request), session.username, count,
    )
    return {"revoked_count": count}


@router.get("/protected/profile")
def profile(session: Session = Depends(get_session)) -> dict:
    return {"username": session.username, "session_id": session.session_id}


@router.get("/protected/admin")
def admin(session: Session = Depends(require_permission("admin"))) -> dict:
    return {"username": session.username, "admin": True}
