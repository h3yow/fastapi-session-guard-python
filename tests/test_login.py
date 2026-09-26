"""登录：三类失败对外不可区分；成功签发会话。"""

from __future__ import annotations

import pytest

from tests.conftest import login

pytestmark = pytest.mark.asyncio


async def test_login_success_issues_token_pair(client):
    resp = await login(client, "alice", "alice-pass-123")
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"] and body["refresh_token"]
    assert body["access_token"] != body["refresh_token"]
    assert body["session_id"]
    assert body["access_expires_at"] < body["refresh_expires_at"] <= body["expires_at"]
    # 请求标识在响应头回显。
    assert resp.headers["x-request-id"]


async def test_login_failures_are_indistinguishable(client):
    """账号不存在 / 口令错误 / 账号禁用：状态码、错误码、文案完全一致。"""
    responses = [
        await login(client, "alice", "wrong-password"),  # 凭证错误
        await login(client, "no-such-user", "whatever"),  # 账号不存在
        await login(client, "carol", "carol-pass-123"),  # 账号被禁用
    ]
    shapes = {(r.status_code, r.json()["code"], r.json()["message"]) for r in responses}
    assert shapes == {(401, "invalid_credentials", "invalid credentials")}
    # 响应里不得泄露具体用户名是否存在（不回显 username）。
    for resp in responses:
        assert "username" not in resp.json()
        assert resp.json()["request_id"] == resp.headers["x-request-id"]


async def test_login_failure_logs_request_id_and_reason(client, decision_logs):
    resp = await login(client, "ghost", "pw")
    request_id = resp.json()["request_id"]
    # 同一条判定日志上必须同时带请求标识与判定依据。
    hits = [
        r
        for r in decision_logs.records
        if getattr(r, "request_id", None) == request_id
        and "auth decision" in r.getMessage()
        and "invalid_credentials" in r.getMessage()
    ]
    assert hits, [r.getMessage() for r in decision_logs.records]
