"""HTTP routes: login, refresh, session management and protected resources."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.auth import AuthError
from app.deps import AppContext, get_context, get_session, require_permission
from app.models import DenyReason, Session, TokenPair

logger = logging.getLogger("session_guard")

router = APIRouter()


class LoginBody(BaseModel):
    username: str
    password: str
    source: str = ""  # client/device identifier, shown in the session list


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
    response = _pair_response(pair)
    response["source"] = body.source
    return response


@router.post("/refresh")
def refresh(body: RefreshBody, request: Request) -> dict:
    ctx: AppContext = get_context(request)
    try:
        pair = ctx.auth.refresh(body.refresh_token)
    except AuthError as err:
        raise _auth_error_response(request, err)
    return _pair_response(pair)


# -- session management --------------------------------------------------

def _session_view(session: Session) -> dict:
    return {
        "session_id": session.session_id,
        "source": session.source,
        "issued_at": session.issued_at,
        "access_expires_at": session.access_expires_at,
        "refresh_expires_at": session.refresh_expires_at,
    }


def _not_found_response(request: Request, detail: str) -> HTTPException:
    rid = request.headers.get("x-request-id", "-")
    logger.info(
        "deny request_id=%s path=%s reason=%s detail=%s",
        rid, request.url.path, DenyReason.SESSION_NOT_FOUND.value, detail,
    )
    return HTTPException(
        status_code=404,
        detail={"reason": DenyReason.SESSION_NOT_FOUND.value,
                "detail": detail, "request_id": rid},
    )


@router.get("/protected/sessions")
def list_sessions(request: Request, caller: Session = Depends(get_session)) -> dict:
    ctx: AppContext = get_context(request)
    sessions = ctx.auth.list_sessions(caller.username)
    rid = request.headers.get("x-request-id", "-")
    logger.info(
        "allow request_id=%s path=/protected/sessions user=%s count=%d",
        rid, caller.username, len(sessions),
    )
    return {"sessions": [_session_view(s) for s in sessions]}


@router.post("/protected/sessions/{session_id}/logout")
def logout_session(session_id: str, request: Request,
                   caller: Session = Depends(get_session)) -> dict:
    ctx: AppContext = get_context(request)
    rid = request.headers.get("x-request-id", "-")
    try:
        ctx.auth.logout(caller.username, session_id)
    except AuthError as err:
        if err.reason is DenyReason.SESSION_NOT_FOUND:
            raise _not_found_response(request, f"session_id={session_id}")
        raise _auth_error_response(request, err)
    logger.info(
        "allow request_id=%s path=%s user=%s action=logout session_id=%s",
        rid, request.url.path, caller.username, session_id,
    )
    return {"status": "revoked", "session_id": session_id}


@router.post("/protected/sessions/logout-all")
def logout_all(request: Request, caller: Session = Depends(get_session)) -> dict:
    ctx: AppContext = get_context(request)
    rid = request.headers.get("x-request-id", "-")
    count = ctx.auth.logout_all(caller.username)
    logger.info(
        "allow request_id=%s path=%s user=%s action=logout-all revoked=%d",
        rid, request.url.path, caller.username, count,
    )
    return {"status": "revoked", "revoked": count}


@router.get("/protected/profile")
def profile(session: Session = Depends(get_session)) -> dict:
    return {"username": session.username, "session_id": session.session_id}


@router.get("/protected/admin")
def admin(session: Session = Depends(require_permission("admin"))) -> dict:
    return {"username": session.username, "admin": True}
