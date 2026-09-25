"""Refresh: rotation, single-use semantics, replay, and concurrency."""

import logging
from concurrent.futures import ThreadPoolExecutor

from tests.conftest import auth_headers, login

logger = logging.getLogger("session_guard.test")


def _refresh(client, token, request_id):
    return client.post(
        "/refresh", json={"refresh_token": token},
        headers={"X-Request-ID": request_id},
    )


def test_sequential_refresh_rotates_tokens(client):
    pair1 = login(client, "alice", "alice-pass").json()
    r = _refresh(client, pair1["refresh_token"], "req-seq-1")
    assert r.status_code == 200
    pair2 = r.json()
    assert pair2["session_id"] == pair1["session_id"]
    assert pair2["access_token"] != pair1["access_token"]
    assert pair2["refresh_token"] != pair1["refresh_token"]
    # Old access token is invalidated; new one works.
    r_old = client.get("/protected/profile",
                       headers=auth_headers(pair1["access_token"], "req-seq-old"))
    assert r_old.status_code == 401
    assert r_old.json()["detail"]["reason"] == "session_revoked"
    r_new = client.get("/protected/profile",
                       headers=auth_headers(pair2["access_token"], "req-seq-new"))
    assert r_new.status_code == 200
    logger.info("sequential refresh ok session_id=%s", pair2["session_id"])


def test_refresh_token_replay_revokes_session(client, caplog):
    pair1 = login(client, "alice", "alice-pass").json()
    pair2 = _refresh(client, pair1["refresh_token"], "req-replay-1").json()
    # Replay the rotated-out refresh token.
    r = _refresh(client, pair1["refresh_token"], "req-replay-2")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "refresh_reused"
    assert r.json()["detail"]["request_id"] == "req-replay-2"
    # Deterministic rule: the whole session is now dead, even the new token.
    r2 = client.get("/protected/profile",
                    headers=auth_headers(pair2["access_token"], "req-replay-3"))
    assert r2.status_code == 401
    assert r2.json()["detail"]["reason"] == "session_revoked"
    # And the current refresh token is dead too.
    r3 = _refresh(client, pair2["refresh_token"], "req-replay-4")
    assert r3.status_code == 401
    assert r3.json()["detail"]["reason"] == "session_revoked"
    assert "reason=refresh_reused" in caplog.text
    logger.info("replay detected; session revoked request_id=req-replay-2")


def test_concurrent_refresh_single_winner_then_revoked(client):
    pair = login(client, "alice", "alice-pass").json()
    token = pair["refresh_token"]
    n = 8
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(
            lambda i: _refresh(client, token, f"req-conc-{i}"), range(n)
        ))
    codes = [r.status_code for r in results]
    reasons = [
        r.json()["detail"]["reason"] if r.status_code == 401 else "ok"
        for r in results
    ]
    logger.info("concurrent refresh results=%s", list(zip(codes, reasons)))
    # Exactly one winner; everyone else gets refresh_reused.
    assert codes.count(200) == 1
    assert reasons.count("refresh_reused") == n - 1
    # Session is revoked by the concurrent reuse: winner's token is dead.
    winner = next(r for r in results if r.status_code == 200).json()
    r = client.get("/protected/profile",
                   headers=auth_headers(winner["access_token"], "req-conc-after"))
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_revoked"


def test_refresh_expired(client, clock):
    pair = login(client, "alice", "alice-pass").json()
    clock.advance(3601)  # beyond refresh_ttl
    r = _refresh(client, pair["refresh_token"], "req-exp-1")
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "session_expired"
    logger.info("refresh after expiry denied reason=session_expired")
