"""日志配置：所有判定日志带请求标识，便于测试与排障时按请求追踪。

通过自定义 Logger 在记录产生时即注入 request_id（取自 contextvar），
因此无论是 stderr handler 还是 pytest 的 caplog handler，都能在同一条
LogRecord 上读到 ``record.request_id``。
"""

from __future__ import annotations

import contextvars
import logging
import sys

LOGGER_NAME = "session_guard"

# 当前请求的标识，由中间件设置；判定日志自动带上。
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")


class RequestIdLogger(logging.Logger):
    def makeRecord(
        self,
        name,
        level,
        fn,
        lno,
        msg,
        args,
        exc_info,  # type: ignore[override]
        func=None,
        extra=None,
        sinfo=None,
    ):
        record = super().makeRecord(name, level, fn, lno, msg, args, exc_info, func, extra, sinfo)
        record.request_id = request_id_var.get()
        return record


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = request_id_var.get()
        return True


_CONFIGURED = False


def reset_logging() -> None:
    """恢复初始状态（测试隔离用）。"""
    global _CONFIGURED
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.propagate = True
    _CONFIGURED = False


def configure_logging(level: int = logging.INFO, *, attach_stderr: bool = True) -> logging.Logger:
    """配置根业务 logger（幂等，便于测试重复调用）。

    attach_stderr=False 时仅保证 request_id 注入与级别设置，日志继续向 root
    传播，便于 pytest caplog 捕获。
    """
    global _CONFIGURED
    logging.setLoggerClass(RequestIdLogger)
    logger = logging.getLogger(LOGGER_NAME)
    # 若 logger 在 setLoggerClass 之前已被创建，则补挂 makeRecord 方法。
    if not isinstance(logger, RequestIdLogger):
        logger.__class__ = RequestIdLogger
    logger.setLevel(level)

    if not attach_stderr:
        # 测试模式先重置，避免此前真实模式留下的 stderr handler 阻断传播。
        reset_logging()
        logger.setLevel(level)
        return logger

    if not _CONFIGURED:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s [request_id=%(request_id)s] %(name)s: %(message)s"
            )
        )
        handler.addFilter(RequestIdFilter())
        logger.addHandler(handler)
        logger.propagate = False
        _CONFIGURED = True
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
