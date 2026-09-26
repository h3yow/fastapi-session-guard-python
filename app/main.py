"""应用工厂：组装中间件、存储、服务、演示数据与统一错误响应。"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.auth import AuthService
from app.clock import system_time
from app.config import Settings
from app.errors import AuthError
from app.logging_setup import configure_logging, get_logger, request_id_var
from app.middleware import RequestIdMiddleware
from app.routes import router
from app.seed import seed_users
from app.store import SessionStore, UserStore


def create_app(
    settings: Settings | None = None,
    time_fn=None,
    configure_logs: bool = True,
) -> FastAPI:
    settings = settings or Settings()
    if configure_logs:
        configure_logging(logging.INFO, attach_stderr=True)
    else:
        # 测试模式：日志继续向 root 传播，供 pytest caplog 捕获；
        # 同时保证 request_id 仍被注入到每条记录。
        configure_logging(logging.DEBUG, attach_stderr=False)
    logger = get_logger()

    users = UserStore()
    if settings.seed_users:
        seed_users(users)
    sessions = SessionStore()
    auth_service = AuthService(users, sessions, settings, time_fn or system_time)

    app = FastAPI(
        title="Local Session Guard",
        version="0.1.0",
        description="本地可复现的登录、会话续期与访问控制服务。",
    )
    app.state.auth_service = auth_service
    app.state.user_store = users
    app.state.session_store = sessions
    app.add_middleware(RequestIdMiddleware)
    app.include_router(router)

    @app.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
        # 统一错误体：code 可机读区分拒绝原因，request_id 可关联判定日志。
        body = {
            "code": exc.code,
            "message": exc.message,
            "request_id": request_id_var.get(),
        }
        logger.info(
            "http rejection code=%s status=%s reason=%s",
            exc.code,
            exc.status_code,
            exc.message,
        )
        return JSONResponse(status_code=exc.status_code, content=body)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    logger.info(
        "application created access_ttl=%s refresh_ttl=%s session_ttl=%s seeded=%s",
        settings.access_ttl,
        settings.refresh_ttl,
        settings.session_ttl,
        settings.seed_users,
    )
    return app
