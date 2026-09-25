"""HTTP routes: login, refresh, and protected resources."""

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
        pair = ctx.auth.login(body.username, body.password)
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


@router.get("/protected/profile")
def profile(session: Session = Depends(get_session)) -> dict:
    return {"username": session.username, "session_id": session.session_id}


@router.get("/protected/admin")
def admin(session: Session = Depends(require_permission("admin"))) -> dict:
    return {"username": session.username, "admin": True}
