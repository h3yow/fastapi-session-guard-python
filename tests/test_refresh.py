"""会话续期：正常顺序续期、旧凭证失效、未知凭证拒绝。"""

from __future__ import annotations

import pytest

from tests.conftest import login

pytestmark = pytest.mark.asyncio


async def _login_alice(client) -> dict:
    resp = await login(client, "alice", "alice-pass-123")
    assert resp.status_code == 200
    return resp.json()


async def test_refresh_rotates_credentials(client):
    first = await _login_alice(client)
    resp = await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert resp.status_code == 200
    second = resp.json()
    assert second["session_id"] == first["session_id"]
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]


async def test_old_refresh_token_fails_and_revokes_whole_session(client):
    """旧续期凭证再次使用 => 重放 => 整个会话（含新凭证）失效。"""
    first = await _login_alice(client)
    second = (
        await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    ).json()

    # 新凭证有效
    ok = await client.get(
        "/protected/whoami",
        headers={"Authorization": f"Bearer {second['access_token']}"},
    )
    assert ok.status_code == 200

    # 重放旧凭证
    replay = await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401
    assert replay.json()["code"] == "session_revoked"

    # 整个会话失效：重放前刚换发的新凭证也不可用，且原因可区分
    after = await client.get(
        "/protected/whoami",
        headers={"Authorization": f"Bearer {second['access_token']}"},
    )
    assert after.status_code == 401
    assert after.json()["code"] == "session_revoked"

    # 已吊销会话上再续期（无论用哪一代凭证）同样稳定判定为 revoked
    again = await client.post("/auth/refresh", json={"refresh_token": second["refresh_token"]})
    assert again.status_code == 401
    assert again.json()["code"] == "session_revoked"


async def test_sequential_refresh_chain_is_not_false_positive(client):
    """正常顺序续期多代不得被误判为重放。"""
    pair = await _login_alice(client)
    for _ in range(4):
        resp = await client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert resp.status_code == 200, resp.text
        pair = resp.json()
    who = await client.get(
        "/protected/whoami", headers={"Authorization": f"Bearer {pair['access_token']}"}
    )
    assert who.status_code == 200


async def test_unknown_refresh_token_rejected(client):
    resp = await client.post("/auth/refresh", json={"refresh_token": "never-issued"})
    assert resp.status_code == 401
    # 未知凭证与重放可区分：不会吊销任何会话
    assert resp.json()["code"] == "refresh_invalid"


async def test_refresh_replay_logs_request_id_and_reason(client, decision_logs):
    first = await _login_alice(client)
    await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    replay = await client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    request_id = replay.json()["request_id"]
    hits = [
        r
        for r in decision_logs.records
        if getattr(r, "request_id", None) == request_id
        and "refresh_token_replay" in r.getMessage()
        and "session_revoked" in r.getMessage()
    ]
    assert hits, [r.getMessage() for r in decision_logs.records]
