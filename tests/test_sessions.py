"""Multi-session management: coexistence, listing visibility, logout
(single + all), logout/refresh races, capacity eviction and live account
state changes."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from tests.conftest import bearer, login

logger = logging.getLogger("session_guard.test")


def _refresh(client, token, request_id):
    return client.post(
        "/refresh", json={"refresh_token": token},
        headers={"X-Request-ID": request_id},
    )


# -- coexistence & source -------------------------------------------------

def test_multiple_sessions_coexist_and_are_independent(client):
    p1 = login(client, "alice", "alice-pass", source="phone").json()
    p2 = login(client, "alice", "alice-pass", source="laptop").json()
    assert p1["session_id"] != p2["session_id"]

    r1 = client.get("/protected/profile", headers=bearer(p1["access_token"], "req-multi-1"))
    r2 = client.get("/protected/profile", headers=bearer(p2["access_token"], "req-multi-2"))
    assert r1.status_code == r2.status_code == 200

    # Refreshing one rotates only that session's tokens.
    p1b = _refresh(client, p1["refresh_token"], "req-multi-3").json()
    r_old = client.get("/protected/profile",
                       headers=bearer(p1["access_token"], "req-multi-4"))
    assert r_old.status_code == 401
    assert r_old.json()["detail"]["reason"] == "session_revoked"
    r_other = client.get("/protected/profile",
                         headers=bearer(p2["access_token"], "req-multi-5"))
    assert r_other.status_code == 200
    r_new = client.get("/protected/profile",
                       headers=bearer(p1b["access_token"], "req-multi-6"))
    assert r_new.status_code == 200
    logger.info("two sessions coexist; rotation is scoped to one session")


# -- listing visibility ---------------------------------------------------

def test_session_list_shows_source_and_times(client):
    p1 = login(client, "alice", "alice-pass", source="phone").json()
    p2 = login(client, "alice", "alice-pass", source="laptop").json()
    r = client.get("/protected/sessions",
                   headers=bearer(p1["access_token"], "req-list-1"))
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert len(sessions) == 2
    by_id = {s["session_id"]: s for s in sessions}
    for sid, source in [(p1["session_id"], "phone"), (p2["session_id"], "laptop")]:
        view = by_id[sid]
        assert view["source"] == source
        assert view["issued_at"] > 0
        assert view["refresh_expires_at"] > view["issued_at"]
        assert view["access_expires_at"] > view["issued_at"]
    assert [s["session_id"] for s in sessions] == [p1["session_id"], p2["session_id"]]
    logger.info("session list exposes source/issued_at/expiry")


def test_session_list_is_scoped_to_caller(client, caplog):
    login(client, "alice", "alice-pass", source="alice-phone").json()
    bob = login(client, "bob", "bob-pass", source="bob-pc").json()
    r = client.get("/protected/sessions",
                   headers=bearer(bob["access_token"], "req-list-scope-1"))
    assert r.status_code == 200
    sources = [s["source"] for s in r.json()["sessions"]]
    assert sources == ["bob-pc"]
    assert "req-list-scope-1" in caplog.text
    logger.info("user can only see own sessions")


def test_session_list_requires_authentication(client):
    r = client.get("/protected/sessions", headers={"X-Request-ID": "req-list-auth-1"})
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "missing_session"


# -- single logout --------------------------------------------------------

def test_logout_single_session_does_not_affect_siblings(client):
    p1 = login(client, "alice", "alice-pass", source="phone").json()
    p2 = login(client, "alice", "alice-pass", source="laptop").json()
    r = client.post(f"/protected/sessions/{p1['session_id']}/logout",
                    headers=bearer(p2["access_token"], "req-lo-1"))
    assert r.status_code == 200
    assert r.json() == {"status": "revoked", "session_id": p1["session_id"]}

    r_access = client.get("/protected/profile",
                          headers=bearer(p1["access_token"], "req-lo-2"))
    assert r_access.status_code == 401
    assert r_access.json()["detail"]["reason"] == "session_revoked"
    r_refresh = _refresh(client, p1["refresh_token"], "req-lo-3")
    assert r_refresh.status_code == 401
    assert r_refresh.json()["detail"]["reason"] == "session_revoked"
    assert client.get("/protected/profile",
                      headers=bearer(p2["access_token"], "req-lo-4")).status_code == 200
    listing = client.get("/protected/sessions",
                         headers=bearer(p2["access_token"], "req-lo-5")).json()["sessions"]
    assert [s["session_id"] for s in listing] == [p2["session_id"]]
    logger.info("single logout is immediate and scoped")


def test_logout_unknown_or_foreign_session_is_404(client, caplog):
    alice = login(client, "alice", "alice-pass", source="phone").json()
    bob = login(client, "bob", "bob-pass", source="pc").json()

    r = client.post(f"/protected/sessions/{alice['session_id']}/logout",
                    headers=bearer(bob["access_token"], "req-lof-1"))
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "session_not_found"
    r = client.post("/protected/sessions/does-not-exist/logout",
                    headers=bearer(bob["access_token"], "req-lof-2"))
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "session_not_found"
    assert client.get("/protected/profile",
                      headers=bearer(alice["access_token"], "req-lof-3")).status_code == 200
    assert "reason=session_not_found" in caplog.text
    assert "req-lof-1" in caplog.text
    logger.info("foreign/missing logout targets -> session_not_found")


def test_logout_twice_is_not_found(client):
    p1 = login(client, "alice", "alice-pass", source="phone").json()
    p2 = login(client, "alice", "alice-pass", source="laptop").json()
    r = client.post(f"/protected/sessions/{p1['session_id']}/logout",
                    headers=bearer(p2["access_token"], "req-lo2-1"))
    assert r.status_code == 200
    r = client.post(f"/protected/sessions/{p1['session_id']}/logout",
                    headers=bearer(p2["access_token"], "req-lo2-2"))
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "session_not_found"


# -- logout all -----------------------------------------------------------

def test_logout_all_revokes_only_caller_sessions(client):
    a1 = login(client, "alice", "alice-pass", source="a1").json()
    a2 = login(client, "alice", "alice-pass", source="a2").json()
    b1 = login(client, "bob", "bob-pass", source="b1").json()

    r = client.post("/protected/sessions/logout-all",
                    headers=bearer(a1["access_token"], "req-loall-1"))
    assert r.status_code == 200
    assert r.json() == {"status": "revoked", "revoked": 2}

    for p, rid in [(a1, "req-loall-2"), (a2, "req-loall-3")]:
        rr = client.get("/protected/profile", headers=bearer(p["access_token"], rid))
        assert rr.status_code == 401
        assert rr.json()["detail"]["reason"] == "session_revoked"
        assert _refresh(client, p["refresh_token"], rid + "r").status_code == 401
    assert client.get("/protected/profile",
                      headers=bearer(b1["access_token"], "req-loall-4")).status_code == 200
    logger.info("logout-all is immediate, complete and account-scoped")


def test_logout_all_with_no_active_sessions_returns_zero(client):
    ctx = client.app.state.ctx
    assert ctx.auth.logout_all("nobody") == 0


# -- logout vs concurrent refresh ----------------------------------------

def test_logout_racing_refresh_has_one_stable_outcome(client):
    p = login(client, "alice", "alice-pass", source="phone").json()
    sid, rt, at = p["session_id"], p["refresh_token"], p["access_token"]
    n = 10

    refreshed_tokens = []

    def call(i):
        if i % 2 == 0:
            resp = _refresh(client, rt, f"req-race-r{i}")
            if resp.status_code == 200:
                refreshed_tokens.append(resp.json()["access_token"])
            return ("refresh", resp.status_code)
        return ("logout", client.post(
            f"/protected/sessions/{sid}/logout",
            headers=bearer(at, f"req-race-l{i}")).status_code)

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(call, range(n)))
    logger.info("race results=%s", results)

    # All mutating operations serialize on one store lock. Either the logout
    # commits first (then no refresh can succeed -> exactly one 200), or one
    # refresh commits first and a later logout revokes the rotated session
    # (two 200s, one of each kind). Nothing else can happen, and in both
    # cases the final session state is identically "revoked".
    total_oks = sum(1 for _, code in results if code == 200)
    logout_oks = sum(1 for kind, code in results if kind == "logout" and code == 200)
    refresh_oks = sum(1 for kind, code in results if kind == "refresh" and code == 200)
    assert total_oks in {1, 2}
    assert logout_oks <= 1 and refresh_oks <= 1
    if total_oks == 2:
        assert logout_oks == 1 and refresh_oks == 1

    # Deterministic end state: every token that ever existed is dead.
    for token in [at, *refreshed_tokens]:
        rr = client.get("/protected/profile",
                        headers=bearer(token, "req-race-after-access"))
        assert rr.status_code == 401
    # And no refresh can ever succeed again after the dust settles.
    r_refresh = _refresh(client, rt, "req-race-after-2")
    assert r_refresh.status_code == 401
    assert r_refresh.json()["detail"]["reason"] in {"session_revoked", "refresh_reused"}


def test_logout_after_refresh_committed_blocks_new_refresh(client):
    p = login(client, "alice", "alice-pass", source="phone").json()
    p2 = _refresh(client, p["refresh_token"], "req-lr-1").json()
    assert p2["session_id"] == p["session_id"]
    r = client.post(f"/protected/sessions/{p['session_id']}/logout",
                    headers=bearer(p2["access_token"], "req-lr-2"))
    assert r.status_code == 200
    assert _refresh(client, p["refresh_token"], "req-lr-3").json()["detail"]["reason"] \
        in {"session_revoked", "refresh_reused"}
    r3 = _refresh(client, p2["refresh_token"], "req-lr-4")
    assert r3.status_code == 401
    assert r3.json()["detail"]["reason"] == "session_revoked"


# -- capacity eviction ----------------------------------------------------

def test_cap_evicts_oldest_session_deterministically(app_factory, caplog):
    client = TestClient(app_factory(max_sessions_per_user=2))
    p1 = login(client, "alice", "alice-pass", source="phone").json()
    p2 = login(client, "alice", "alice-pass", source="laptop").json()
    p3 = login(client, "alice", "alice-pass", source="watch").json()

    r = client.get("/protected/profile",
                   headers=bearer(p1["access_token"], "req-cap-1"))
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_evicted"
    r_ref = _refresh(client, p1["refresh_token"], "req-cap-2")
    assert r_ref.status_code == 401
    assert r_ref.json()["detail"]["reason"] == "session_evicted"
    assert client.get("/protected/profile",
                      headers=bearer(p2["access_token"], "req-cap-3")).status_code == 200
    assert client.get("/protected/profile",
                      headers=bearer(p3["access_token"], "req-cap-4")).status_code == 200
    listing = client.get("/protected/sessions",
                         headers=bearer(p2["access_token"], "req-cap-5")).json()["sessions"]
    assert {s["session_id"] for s in listing} == {p2["session_id"], p3["session_id"]}
    assert f"session_id={p1['session_id']}" in caplog.text
    assert "reason=session_evicted" in caplog.text
    logger.info("cap eviction: oldest session, stable session_evicted reason")


def test_eviction_is_per_user_and_seniority_survives_refresh(app_factory):
    client = TestClient(app_factory(max_sessions_per_user=2))
    a1 = login(client, "alice", "alice-pass", source="a1").json()
    a2 = login(client, "alice", "alice-pass", source="a2").json()
    a1b = _refresh(client, a1["refresh_token"], "req-capr-1").json()
    login(client, "bob", "bob-pass", source="b1")
    login(client, "bob", "bob-pass", source="b2")
    a3 = login(client, "alice", "alice-pass", source="a3").json()
    r = client.get("/protected/profile",
                   headers=bearer(a1b["access_token"], "req-capr-2"))
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_evicted"
    assert a3["session_id"] != a1["session_id"]


def test_expired_sessions_do_not_count_toward_cap(client, clock):
    ctx = client.app.state.ctx
    ctx.auth._max_sessions = 2
    p1 = login(client, "alice", "alice-pass", source="phone").json()
    login(client, "alice", "alice-pass", source="laptop")
    clock.advance(3601)
    p3 = login(client, "alice", "alice-pass", source="watch").json()
    p4 = login(client, "alice", "alice-pass", source="tv").json()
    assert client.get("/protected/profile",
                      headers=bearer(p3["access_token"], "req-cape-1")).status_code == 200
    assert client.get("/protected/profile",
                      headers=bearer(p4["access_token"], "req-cape-2")).status_code == 200
    assert p1["session_id"] != p3["session_id"]


# -- live account state changes ------------------------------------------

def test_disabling_account_blocks_existing_sessions_immediately(client, users, caplog):
    p = login(client, "bob", "bob-pass", source="phone").json()
    assert client.get("/protected/profile",
                      headers=bearer(p["access_token"], "req-dis-1")).status_code == 200

    users.set_disabled("bob", True)
    r = client.get("/protected/profile",
                   headers=bearer(p["access_token"], "req-dis-2"))
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "account_disabled"
    r_ref = _refresh(client, p["refresh_token"], "req-dis-3")
    assert r_ref.status_code == 401
    assert r_ref.json()["detail"]["reason"] == "account_disabled"
    r_list = client.get("/protected/sessions",
                        headers=bearer(p["access_token"], "req-dis-4"))
    assert r_list.status_code == 401
    assert r_list.json()["detail"]["reason"] == "account_disabled"
    assert "reason=account_disabled" in caplog.text
    logger.info("disabled account: existing sessions blocked at once")


def test_reenabling_account_restores_existing_sessions(client, users):
    p = login(client, "bob", "bob-pass", source="phone").json()
    users.set_disabled("bob", True)
    assert client.get("/protected/profile",
                      headers=bearer(p["access_token"], "req-en-1")).status_code == 401
    users.set_disabled("bob", False)
    r = client.get("/protected/profile",
                   headers=bearer(p["access_token"], "req-en-2"))
    assert r.status_code == 200
    assert _refresh(client, p["refresh_token"], "req-en-3").status_code == 200
    logger.info("re-enabled account: existing sessions restored at once")


def test_disabled_account_still_cannot_login(client, users):
    users.set_disabled("bob", True)
    r = login(client, "bob", "bob-pass", source="phone")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "invalid_credentials"


def test_account_state_change_does_not_touch_other_users(client, users):
    alice = login(client, "alice", "alice-pass", source="a-phone").json()
    login(client, "bob", "bob-pass", source="b-phone")
    users.set_disabled("bob", True)
    assert client.get("/protected/profile",
                      headers=bearer(alice["access_token"], "req-iso-1")).status_code == 200
    users.set_disabled("alice", True)
    assert client.get("/protected/profile",
                      headers=bearer(alice["access_token"], "req-iso-2")).status_code == 401
    users.set_disabled("alice", False)
    users.set_disabled("bob", False)
    # bob's old session is usable again once re-enabled.
    bob = client.app.state.ctx
    sessions = bob.auth.list_sessions("bob")
    assert len(sessions) == 1
