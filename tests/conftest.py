import logging
import time

import pytest
from fastapi.testclient import TestClient

from app.models import User
from app.auth import hash_password
from app.store import UserStore
from main import create_app

logger = logging.getLogger("session_guard.test")


class Clock:
    """Deterministic, manually advanced clock."""

    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(time, "time", c)
    return c


@pytest.fixture
def users() -> UserStore:
    return UserStore(
        {
            "alice": User(
                username="alice",
                password_hash=hash_password("alice-pass"),
                permissions=frozenset({"admin"}),
            ),
            "bob": User(
                username="bob",
                password_hash=hash_password("bob-pass"),
                permissions=frozenset(),
            ),
            "carol": User(
                username="carol",
                password_hash=hash_password("carol-pass"),
                disabled=True,
            ),
        }
    )


@pytest.fixture
def app_factory(users):
    created = []

    def _factory(max_sessions_per_user: int = 5):
        app = create_app(
            users=users, access_ttl=300.0, refresh_ttl=3600.0,
            max_sessions_per_user=max_sessions_per_user,
        )
        created.append(app)
        return app

    return _factory


@pytest.fixture
def app(users):
    return create_app(users=users, access_ttl=300.0, refresh_ttl=3600.0)


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=True)


def login(client, username, password, source=""):
    body = {"username": username, "password": password}
    if source:
        body["source"] = source
    return client.post("/login", json=body)


def bearer(token, request_id=None):
    headers = {"Authorization": f"Bearer {token}"}
    if request_id is not None:
        headers["X-Request-ID"] = request_id
    return headers


def auth_headers(token, request_id):
    return {"Authorization": f"Bearer {token}", "X-Request-ID": request_id}
