"""并发边界：同一续期凭证被并发使用时的确定性行为。

规则：同一张续期凭证在整个会话生命周期内最多成功一次。并发争抢时
恰有一次成功换发，另一次识别为旧凭证重放并使整个会话失效；因此成功
换发出的新凭证也立即不可用。多客户端各自持有不同会话互不影响。
"""

from __future__ import annotations

import asyncio

import pytest

from tests.conftest import login

pytestmark = pytest.mark.asyncio


async def _login(client, username: str = "alice", password: str = "alice-pass-123") -> dict:
    resp = await login(client, username, password)
    assert resp.status_code == 200
    return resp.json()


async def test_concurrent_same_refresh_token_has_single_winner(client):
    pair = await _login(client)
    original_refresh = pair["refresh_token"]

    # 两个客户端同时使用同一张续期凭证。
    async def use_token(i: int):
        return await client.post(
            "/auth/refresh",
            json={"refresh_token": original_refresh},
            headers={"X-Request-ID": f"concurrent-{i}"},
        )

    r1, r2 = await asyncio.gather(use_token(1), use_token(2))

    statuses = sorted((r1.status_code, r2.status_code))
    # 恰一个成功（200），另一个 401
    assert statuses == [200, 401], (r1.text, r2.text)

    winner = r1 if r1.status_code == 200 else r2
    loser = r2 if r1.status_code == 200 else r1
    assert loser.json()["code"] == "session_revoked"
    # 成功响应是凭证对而非错误体
    assert "access_token" in winner.json()

    # 整个会话已失效：赢家拿到的新凭证也不可再用
    who = await client.get(
        "/protected/whoami",
        headers={"Authorization": f"Bearer {winner.json()['access_token']}"},
    )
    assert who.status_code == 401
    assert who.json()["code"] == "session_revoked"


async def test_concurrent_replay_after_success_revokes_session(client):
    """成功续期后立刻并发重放旧凭证（与未知凭证混合），结果仍确定。"""
    pair = await _login(client)
    await client.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})

    old = pair["refresh_token"]
    r_old, r_unknown = await asyncio.gather(
        client.post("/auth/refresh", json={"refresh_token": old}),
        client.post("/auth/refresh", json={"refresh_token": "made-up-token"}),
    )
    assert r_old.status_code == 401
    assert r_old.json()["code"] == "session_revoked"
    # 未知凭证不得牵连任何会话，错误码可区分
    assert r_unknown.json()["code"] == "refresh_invalid"


async def test_concurrent_distinct_sessions_do_not_interfere(client):
    """多客户端并发续期各自的会话：全部成功，互不串扰。"""
    pairs = []
    for _ in range(5):
        pairs.append(await _login(client))

    responses = await asyncio.gather(
        *[client.post("/auth/refresh", json={"refresh_token": p["refresh_token"]}) for p in pairs]
    )
    assert all(r.status_code == 200 for r in responses), [r.text for r in responses]
    session_ids = {r.json()["session_id"] for r in responses}
    assert session_ids == {p["session_id"] for p in pairs}


async def test_concurrent_decisions_logged_with_request_ids(client, decision_logs):
    pair = await _login(client)
    await asyncio.gather(
        client.post(
            "/auth/refresh",
            json={"refresh_token": pair["refresh_token"]},
            headers={"X-Request-ID": "rid-A"},
        ),
        client.post(
            "/auth/refresh",
            json={"refresh_token": pair["refresh_token"]},
            headers={"X-Request-ID": "rid-B"},
        ),
    )
    # 两个请求标识都应在判定/访问日志中可检索到。
    messages = [r.getMessage() for r in decision_logs.records]
    assert any("rid-A" in m for m in messages)
    assert any("rid-B" in m for m in messages)
    assert any("refresh_token_replay" in m or "refresh allowed" in m for m in messages)
