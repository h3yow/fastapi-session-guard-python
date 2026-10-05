"""Multi-session management: listing, logout, cap eviction, account state."""

import logging
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from main import create_app
from tests.conftest import auth_headers, login

logger = logging.getLogger("session_guard.test")


def _login(client, username, password, source="", request_id="req-login"):
    return client.post(
        "/login",
        json={"username": username, "password": password, "source": source},
        headers={"X-Request-ID": request_id},
    )


def _list(client, token, request_id="req-list"):
    return client.get("/sessions", headers=auth_headers(token, request_id))


def _delete(client, token, session_id, request_id="req-del"):
    return client.delete(f"/sessions/{session_id}",
                         headers=auth_headers(token, request_id))


def _delete_all(client, token, request_id="req-del-all"):
    return client.delete("/sessions", headers=auth_headers(token, request_id))


def _refresh(client, token, request_id="req-refresh"):
    return client.post("/refresh", json={"refresh_token": token},
                       headers={"X-Request-ID": request_id})


def _profile(client, token, request_id="req-profile"):
    return client.get("/protected/profile", headers=auth_headers(token, request_id))


# -- coexistence & isolation -------------------------------------------------


def test_multi_session_coexist_and_refresh_isolated(client):
    laptop = _login(client, "alice", "alice-pass", "laptop", "req-co-1").json()
    phone = _login(client, "alice", "alice-pass", "phone", "req-co-2").json()
    assert laptop["session_id"] != phone["session_id"]

    # Refreshing the phone session rotates only its own tokens.
    phone2 = _refresh(client, phone["refresh_token"], "req-co-3").json()
    assert phone2["session_id"] == phone["session_id"]
    assert _profile(client, phone["access_token"], "req-co-4").status_code == 401
    assert _profile(client, phone2["access_token"], "req-co-5").status_code == 200
    # The laptop session is completely untouched.
    r = _profile(client, laptop["access_token"], "req-co-6")
    assert r.status_code == 200
    assert r.json()["session_id"] == laptop["session_id"]
    assert _refresh(client, laptop["refresh_token"], "req-co-7").status_code == 200
    logger.info("multi-session coexistence ok; refresh isolated per session")


def test_session_list_shows_only_own_sessions(client):
    a1 = _login(client, "alice", "alice-pass", "laptop", "req-vis-1").json()
    a2 = _login(client, "alice", "alice-pass", "phone", "req-vis-2").json()
    b1 = _login(client, "bob", "bob-pass", "tablet", "req-vis-3").json()

    r = _list(client, a1["access_token"], "req-vis-4")
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert {s["session_id"] for s in sessions} == {a1["session_id"], a2["session_id"]}
    by_id = {s["session_id"]: s for s in sessions}
    assert by_id[a1["session_id"]]["source"] == "laptop"
    assert by_id[a2["session_id"]]["source"] == "phone"
    assert by_id[a1["session_id"]]["current"] is True
    assert by_id[a2["session_id"]]["current"] is False
    for s in sessions:
        assert s["issued_at"] > 0
        assert s["access_expires_at"] > s["issued_at"]
        assert s["refresh_expires_at"] > s["access_expires_at"]

    r_bob = _list(client, b1["access_token"], "req-vis-5")
    assert [s["session_id"] for s in r_bob.json()["sessions"]] == [b1["session_id"]]
    logger.info("session list visibility ok: each account sees only its own")


# -- logout ------------------------------------------------------------------


def test_logout_single_session_leaves_others_alive(client):
    laptop = _login(client, "alice", "alice-pass", "laptop", "req-lo-1").json()
    phone = _login(client, "alice", "alice-pass", "phone", "req-lo-2").json()

    r = _delete(client, laptop["access_token"], phone["session_id"], "req-lo-3")
    assert r.status_code == 200
    assert r.json()["revoked"] == phone["session_id"]

    # The revoked session dies immediately: access and refresh both fail.
    r = _profile(client, phone["access_token"], "req-lo-4")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_revoked"
    r = _refresh(client, phone["refresh_token"], "req-lo-5")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_revoked"
    # Gone from the list too.
    listed = _list(client, laptop["access_token"], "req-lo-6").json()["sessions"]
    assert [s["session_id"] for s in listed] == [laptop["session_id"]]
    # The other session is fully functional.
    assert _profile(client, laptop["access_token"], "req-lo-7").status_code == 200
    assert _refresh(client, laptop["refresh_token"], "req-lo-8").status_code == 200
    logger.info("single logout ok; sibling session unaffected")


def test_logout_foreign_or_unknown_session_is_not_found(client):
    alice = _login(client, "alice", "alice-pass", "laptop", "req-fg-1").json()
    bob = _login(client, "bob", "bob-pass", "tablet", "req-fg-2").json()

    # Alice cannot touch Bob's session; it looks identical to a unknown id.
    r = _delete(client, alice["access_token"], bob["session_id"], "req-fg-3")
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "session_not_found"
    r = _delete(client, alice["access_token"], "no-such-session", "req-fg-4")
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "session_not_found"
    # Bob's session is unharmed.
    assert _profile(client, bob["access_token"], "req-fg-5").status_code == 200
    logger.info("foreign/unknown session logout denied indistinguishably")


def test_logout_all_revokes_every_own_session_only(client):
    a1 = _login(client, "alice", "alice-pass", "laptop", "req-la-1").json()
    a2 = _login(client, "alice", "alice-pass", "phone", "req-la-2").json()
    bob = _login(client, "bob", "bob-pass", "tablet", "req-la-3").json()

    r = _delete_all(client, a1["access_token"], "req-la-4")
    assert r.status_code == 200
    assert r.json()["revoked_count"] == 2

    for pair, rid in ((a1, "req-la-5"), (a2, "req-la-6")):
        r = _profile(client, pair["access_token"], rid)
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "session_revoked"
        r = _refresh(client, pair["refresh_token"], rid + "r")
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "session_revoked"
    # Bob is untouched.
    assert _profile(client, bob["access_token"], "req-la-7").status_code == 200
    logger.info("logout_all revoked 2 own sessions; other account unaffected")


def test_logout_racing_refresh_has_deterministic_final_state(client):
    """Logout vs in-flight refresh: either order, the session ends dead."""
    outcomes = set()
    for i in range(12):
        pair = _login(client, "alice", "alice-pass", f"dev-{i}", f"req-rc-{i}-login").json()
        observer = _login(client, "alice", "alice-pass", "observer", f"req-rc-{i}-obs").json()
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_logout = pool.submit(
                _delete, client, observer["access_token"], pair["session_id"],
                f"req-rc-{i}-logout",
            )
            f_refresh = pool.submit(
                _refresh, client, pair["refresh_token"], f"req-rc-{i}-refresh",
            )
            logout_r, refresh_r = f_logout.result(), f_refresh.result()
        assert logout_r.status_code == 200
        outcomes.add(refresh_r.status_code)
        if refresh_r.status_code == 401:
            # Logout won the lock: refresh must see the revoked session.
            assert refresh_r.json()["detail"]["reason"] == "session_revoked"
            latest = pair
        else:
            # Refresh won, but the logout still revoked the rotated tokens.
            latest = refresh_r.json()
        # Deterministic final state, regardless of who won:
        # no refresh of this session can ever succeed again ...
        r = _refresh(client, latest["refresh_token"], f"req-rc-{i}-after-r")
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "session_revoked"
        # ... access is denied ...
        r = _profile(client, latest["access_token"], f"req-rc-{i}-after-a")
        assert r.status_code == 401
        assert r.json()["detail"]["reason"] == "session_revoked"
        # ... and the session is gone from the account's list.
        ids = [s["session_id"] for s in _list(client, observer["access_token"], f"req-rc-{i}-list").json()["sessions"]]
        assert pair["session_id"] not in ids
    logger.info("logout/refresh race outcomes=%s; final state always revoked", outcomes)


# -- per-account cap & eviction ----------------------------------------------


@pytest.fixture
def capped_client(users):
    app = create_app(users=users, access_ttl=300.0, refresh_ttl=3600.0,
                     max_sessions=3)
    return TestClient(app, raise_server_exceptions=True)


def test_session_cap_evicts_oldest(capped_client):
    client = capped_client
    pairs = [
        _login(client, "alice", "alice-pass", f"dev-{i}", f"req-cap-{i}").json()
        for i in range(4)
    ]
    # The oldest session (dev-0) was evicted by the 4th login.
    r = _profile(client, pairs[0]["access_token"], "req-cap-evicted")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_evicted"
    r = _refresh(client, pairs[0]["refresh_token"], "req-cap-evicted-r")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_evicted"
    # The three newest survive and are exactly what the list returns.
    ids = [s["session_id"] for s in _list(client, pairs[3]["access_token"], "req-cap-list").json()["sessions"]]
    assert ids == [p["session_id"] for p in pairs[1:]]
    for i, p in enumerate(pairs[1:], start=1):
        assert _profile(client, p["access_token"], f"req-cap-ok-{i}").status_code == 200
    logger.info("cap=3: 4th login evicted oldest; rejection is session_evicted")


def test_session_cap_is_per_account(capped_client):
    client = capped_client
    for i in range(4):
        _login(client, "alice", "alice-pass", f"a-{i}", f"req-pc-a-{i}")
    bob = _login(client, "bob", "bob-pass", "b-0", "req-pc-b-0").json()
    # Alice is capped at 3, but Bob's fresh session is unaffected.
    assert _profile(client, bob["access_token"], "req-pc-b-1").status_code == 200
    ids = [s["session_id"] for s in _list(client, bob["access_token"], "req-pc-b-2").json()["sessions"]]
    assert ids == [bob["session_id"]]
    logger.info("session cap is per-account; other accounts unaffected")


# -- account state changes ---------------------------------------------------


def test_account_disable_enable_applies_to_live_sessions(client, users):
    pair = _login(client, "alice", "alice-pass", "laptop", "req-ds-1").json()
    assert _profile(client, pair["access_token"], "req-ds-2").status_code == 200

    users.set_disabled("alice", True)
    r = _profile(client, pair["access_token"], "req-ds-3")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "account_disabled"
    r = _refresh(client, pair["refresh_token"], "req-ds-4")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "account_disabled"
    # Login while disabled stays indistinguishable from bad credentials.
    r = _login(client, "alice", "alice-pass", "phone", "req-ds-5")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "invalid_credentials"

    # Re-enabling revives the existing session without a new login.
    users.set_disabled("alice", False)
    assert _profile(client, pair["access_token"], "req-ds-6").status_code == 200
    assert _refresh(client, pair["refresh_token"], "req-ds-7").status_code == 200
    logger.info("disable/enable applied live to existing sessions")


def test_account_disable_does_not_touch_other_users(client, users):
    alice = _login(client, "alice", "alice-pass", "laptop", "req-do-1").json()
    bob = _login(client, "bob", "bob-pass", "tablet", "req-do-2").json()
    users.set_disabled("alice", True)
    assert _profile(client, alice["access_token"], "req-do-3").status_code == 401
    assert _profile(client, bob["access_token"], "req-do-4").status_code == 200
    logger.info("disabling one account leaves others alone")
