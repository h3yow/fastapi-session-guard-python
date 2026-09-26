"""HTTP 请求/响应模型。"""

from __future__ import annotations

from pydantic import BaseModel


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    session_id: str
    access_expires_at: float
    refresh_expires_at: float
    expires_at: float


class ErrorResponse(BaseModel):
    code: str
    message: str
    request_id: str


class WhoAmIResponse(BaseModel):
    username: str
    roles: list[str]
    session_id: str
    request_id: str


class RolesRequest(BaseModel):
    roles: list[str]
