"""测试夹具：可控时钟、短 TTL 应用、HTTP 客户端与判定日志断言。"""

from __future__ import annotations

import logging

import httpx
import pytest
import pytest_asyncio

from app.config import Settings
from app.logging_setup import LOGGER_NAME
from app.main import create_app

# 短 TTL，便于在不 sleep 的前提下覆盖访问凭证/会话过期。
TEST_SETTINGS = Settings(
    access_ttl=10.0,
    refresh_ttl=60.0,
    session_ttl=600.0,
    seed_users=True,
)


class FakeClock:
    """可手动推进的确定性时间源。"""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def app(clock: FakeClock):
    application = create_app(TEST_SETTINGS, time_fn=clock, configure_logs=False)
    return application


@pytest.fixture
def auth_service(app):
    return app.state.auth_service


@pytest_asyncio.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.fixture
def decision_logs(caplog):
    """捕获 session_guard 的判定/访问日志（同时会被 pytest 打印）。

    返回 caplog 夹具本身；用例中通过 ``decision_logs.records`` 取最新记录。
    """
    caplog.set_level(logging.DEBUG, logger=LOGGER_NAME)
    return caplog


def login_sync(client_factory, username: str, password: str) -> dict:
    raise RuntimeError("use async login() helper instead")


async def login(client: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    return await client.post("/auth/login", json={"username": username, "password": password})


@pytest.fixture
def helpers():
    """供测试复用的小工具集合。"""

    class H:
        @staticmethod
        def auth_header(token: str) -> dict:
            return {"Authorization": f"Bearer {token}"}

        @staticmethod
        def assert_decision_logged(caplog, request_id: str, code: str) -> bool:
            """判定日志中必须同时出现请求标识与判定依据（错误码）。"""
            for record in caplog.records:
                if (
                    getattr(record, "request_id", None) == request_id
                    and code in record.getMessage()
                ):
                    return True
            return False

    return H()
