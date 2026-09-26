"""请求标识中间件。

* 优先采用客户端传入的 ``X-Request-ID``（便于跨系统关联），否则生成新 ID；
* 把 ID 写入 contextvar，判定日志自动携带，并在响应头原样回传；
* 记录一行访问日志（方法、路径、状态、请求 ID）。
"""

from __future__ import annotations

import uuid

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.logging_setup import get_logger, request_id_var

logger = get_logger()

_REQUEST_ID_HEADER = b"x-request-id"
_MAX_REQUEST_ID_LEN = 128


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = ""
        for key, value in scope.get("headers", []):
            if key == _REQUEST_ID_HEADER:
                incoming = value.decode("latin-1", errors="ignore")[:_MAX_REQUEST_ID_LEN]
                break
        request_id = incoming or uuid.uuid4().hex
        token = request_id_var.set(request_id)

        status_code = 0

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = MutableHeaders(scope=message)
                headers.append("X-Request-ID", request_id)
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            logger.info(
                "access %s %s -> %s request_id=%s",
                scope.get("method"),
                scope.get("path"),
                status_code or "error",
                request_id,
            )
            request_id_var.reset(token)
