"""Login: success, and indistinguishable failures."""

import logging

from tests.conftest import login

logger = logging.getLogger("session_guard.test")


def test_login_success(client):
    r = login(client, "alice", "alice-pass")
    assert r.status_code == 200
    body = r.json()
    assert body["access_token"] and body["refresh_token"]
    assert body["token_type"] == "bearer"
    logger.info("login ok session_id=%s", body["session_id"])


def test_login_failures_are_indistinguishable(client, caplog):
    cases = [
        ("alice", "wrong-pass"),   # wrong password
        ("nobody", "whatever"),    # unknown user
        ("carol", "carol-pass"),   # disabled account
    ]
    responses = []
    for username, password in cases:
        r = login(client, username, password)
        assert r.status_code == 401
        responses.append(r.json())
        logger.info(
            "login denied user=%s reason=%s", username, r.json()["detail"]["reason"]
        )
    # Identical externally visible result: no account-existence leak.
    assert responses[0] == responses[1] == responses[2]
    assert responses[0]["detail"]["reason"] == "invalid_credentials"
    # Decision basis is logged for each denial.
    assert caplog.text.count("reason=invalid_credentials") >= 3
