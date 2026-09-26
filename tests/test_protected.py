"""受保护接口：缺失/无效/吊销/过期/权限不足必须可区分；权限变更语义确定。"""

from __future__ import annotations

import pytest

from tests.conftest import login

pytestmark = pytest.mark.asyncio

VIEW = "/protected/view"
ADMIN = "/protected/admin"


async def _tokens(client, username="alice", password="alice-pass-123") -> dict:
    r = await login(client, username, password)
    assert r.status_code == 200
    return r.json()


async def test_access_without_token_is_missing(client):
    r = await client.get(VIEW)
    assert r.status_code == 401
    assert r.json()["code"] == "session_missing"


async def test_access_with_garbage_token_is_invalid(client):
    r = await client.get(VIEW, headers={"Authorization": "Bearer not-a-real-token"})
    assert r.status_code == 401
    assert r.json()["code"] == "session_invalid"


async def test_access_with_wrong_scheme_is_missing(client):
    r = await client.get(VIEW, headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    assert r.json()["code"] == "session_missing"


async def test_expired_access_token_is_distinguished(client, clock):
    tokens = await _tokens(client)
    clock.advance(11.0)  # access_ttl=10s
    r = await client.get(VIEW, headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 401
    assert r.json()["code"] == "session_expired"


async def test_refresh_after_session_lifetime_expired(client, clock):
    tokens = await _tokens(client)
    clock.advance(601.0)  # session_ttl=600s
    r = await client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401
    assert r.json()["code"] == "session_expired"


async def test_permission_denied_is_distinguished(client):
    # bob 只有 view，不能访问 admin
    tokens = await _tokens(client, "bob", "bob-pass-123")
    r = await client.get(ADMIN, headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 403
    body = r.json()
    assert body["code"] == "permission_denied"
    assert "admin" in body["message"]
    assert body["request_id"]


async def test_role_grant_takes_effect_on_next_request(client):
    """权限扩大：已有会话无需重新登录，下一次请求立即获得新范围。"""
    admin = await _tokens(client)
    bob = await _tokens(client, "bob", "bob-pass-123")

    before = await client.get(ADMIN, headers={"Authorization": f"Bearer {bob['access_token']}"})
    assert before.json()["code"] == "permission_denied"

    # 管理员调整 bob 的角色
    grant = await client.post(
        "/admin/users/bob/roles",
        json={"roles": ["view", "admin"]},
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert grant.status_code == 200
    assert grant.json()["profile_version"] == 1

    # 同一会话凭证立刻生效
    after = await client.get(ADMIN, headers={"Authorization": f"Bearer {bob['access_token']}"})
    assert after.status_code == 200, after.text
    assert after.json()["roles"] == ["admin", "view"]
    assert after.json()["profile_version"] == 1


async def test_role_revocation_takes_effect_immediately(client):
    """权限缩小：已有会话的生效范围在下一次请求立即收窄。"""
    admin = await _tokens(client)
    before = await client.get(ADMIN, headers={"Authorization": f"Bearer {admin['access_token']}"})
    assert before.status_code == 200

    # 另一个管理员会话把 alice 降为仅 view（alice 自己仍是 admin，可操作）
    change = await client.post(
        "/admin/users/alice/roles",
        json={"roles": ["view"]},
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    assert change.status_code == 200

    after = await client.get(ADMIN, headers={"Authorization": f"Bearer {admin['access_token']}"})
    assert after.status_code == 403
    assert after.json()["code"] == "permission_denied"
    # view 范围仍然有效，语义稳定
    still_view = await client.get(
        VIEW, headers={"Authorization": f"Bearer {admin['access_token']}"}
    )
    assert still_view.status_code == 200


async def test_disabled_account_sessions_rejected_as_disabled(client):
    """账号被禁用后，已有会话下次请求返回可区分的 account_disabled。"""
    admin = await _tokens(client)
    bob = await _tokens(client, "bob", "bob-pass-123")
    await client.post(
        "/admin/users/bob/disable",
        headers={"Authorization": f"Bearer {admin['access_token']}"},
    )
    r = await client.get(VIEW, headers={"Authorization": f"Bearer {bob['access_token']}"})
    assert r.status_code == 403
    assert r.json()["code"] == "account_disabled"

    # 重新登录也必须失败，且与账号不存在/口令错误不可区分
    relogin = await login(client, "bob", "bob-pass-123")
    assert relogin.json()["code"] == "invalid_credentials"


async def test_revoked_via_logout_is_distinguished(client):
    tokens = await _tokens(client)
    out = await client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert out.status_code == 200
    r = await client.get(VIEW, headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 401
    assert r.json()["code"] == "session_revoked"


async def test_each_rejection_has_distinct_code(client, clock):
    """同一应用实例上收集全部拒绝码，确认彼此可区分。"""
    tokens = await _tokens(client)
    codes = set()
    codes.add((await client.get(VIEW)).json()["code"])
    codes.add((await client.get(VIEW, headers={"Authorization": "Bearer x"})).json()["code"])
    clock.advance(11)
    codes.add(
        (
            await client.get(VIEW, headers={"Authorization": f"Bearer {tokens['access_token']}"})
        ).json()["code"]
    )

    fresh = await _tokens(client, "bob", "bob-pass-123")
    codes.add(
        (
            await client.get(ADMIN, headers={"Authorization": f"Bearer {fresh['access_token']}"})
        ).json()["code"]
    )

    await client.post("/auth/logout", headers={"Authorization": f"Bearer {fresh['access_token']}"})
    codes.add(
        (
            await client.get(VIEW, headers={"Authorization": f"Bearer {fresh['access_token']}"})
        ).json()["code"]
    )

    assert codes == {
        "session_missing",
        "session_invalid",
        "session_expired",
        "permission_denied",
        "session_revoked",
    }


async def test_decision_log_carries_request_id_and_code(client, decision_logs):
    tokens = await _tokens(client, "bob", "bob-pass-123")
    await client.get(
        ADMIN,
        headers={
            "Authorization": f"Bearer {tokens['access_token']}",
            "X-Request-ID": "trace-42",
        },
    )
    hits = [
        r
        for r in decision_logs.records
        if getattr(r, "request_id", None) == "trace-42" and "permission_denied" in r.getMessage()
    ]
    assert hits, [r.getMessage() for r in decision_logs.records]
