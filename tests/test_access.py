"""Access control: distinguishable denials and permission-change semantics."""

import logging

from tests.conftest import auth_headers, login

logger = logging.getLogger("session_guard.test")


def test_missing_session(client):
    r = client.get("/protected/profile", headers={"X-Request-ID": "req-acc-1"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "missing_session"
    assert r.json()["detail"]["request_id"] == "req-acc-1"
    logger.info("no token -> missing_session request_id=req-acc-1")


def test_unknown_token(client):
    r = client.get("/protected/profile",
                   headers=auth_headers("not-a-real-token", "req-acc-2"))
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_revoked"
    logger.info("unknown token -> session_revoked request_id=req-acc-2")


def test_expired_access_token(client, clock):
    pair = login(client, "alice", "alice-pass").json()
    clock.advance(301)  # beyond access_ttl, within refresh_ttl
    r = client.get("/protected/profile",
                   headers=auth_headers(pair["access_token"], "req-acc-3"))
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_expired"
    # ...but the refresh token still works (distinguishable from revocation).
    r2 = client.post("/refresh", json={"refresh_token": pair["refresh_token"]},
                     headers={"X-Request-ID": "req-acc-3b"})
    assert r2.status_code == 200
    logger.info("expired access -> session_expired; refresh still valid")


def test_forbidden_without_permission(client, caplog):
    pair = login(client, "bob", "bob-pass").json()  # bob has no permissions
    r = client.get("/protected/admin",
                   headers=auth_headers(pair["access_token"], "req-acc-4"))
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "forbidden"
    assert "reason=forbidden" in caplog.text
    assert "req-acc-4" in caplog.text
    logger.info("bob -> forbidden request_id=req-acc-4")


def test_permission_change_applies_to_existing_session(client, users):
    pair = login(client, "bob", "bob-pass").json()
    token = pair["access_token"]
    r = client.get("/protected/admin", headers=auth_headers(token, "req-acc-5a"))
    assert r.status_code == 403

    # Grant admin: the existing session immediately gains access.
    users.set_permissions("bob", frozenset({"admin"}))
    r = client.get("/protected/admin", headers=auth_headers(token, "req-acc-5b"))
    assert r.status_code == 200
    logger.info("grant admin -> existing session allowed request_id=req-acc-5b")

    # Revoke admin: the same session immediately loses access.
    users.set_permissions("bob", frozenset())
    r = client.get("/protected/admin", headers=auth_headers(token, "req-acc-5c"))
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "forbidden"
    logger.info("revoke admin -> existing session forbidden request_id=req-acc-5c")


def test_denial_reasons_are_distinguishable(client, clock):
    pair = login(client, "bob", "bob-pass").json()
    token = pair["access_token"]
    results = {}
    results["missing"] = client.get("/protected/profile").json()["detail"]["reason"]
    clock.advance(301)
    results["expired"] = client.get(
        "/protected/profile", headers=auth_headers(token, "req-acc-6")
    ).json()["detail"]["reason"]
    # Fresh session (clock advanced past the first token's expiry).
    fresh = login(client, "bob", "bob-pass").json()
    results["forbidden"] = client.get(
        "/protected/admin", headers=auth_headers(fresh["access_token"], "req-acc-7")
    ).json()["detail"]["reason"]
    assert results == {
        "missing": "missing_session",
        "expired": "session_expired",
        "forbidden": "forbidden",
    }
    assert len(set(results.values()) | {"session_revoked", "refresh_reused"}) == 5
    logger.info("denial reasons distinguishable: %s", results)
