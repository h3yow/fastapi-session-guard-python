"""可注入的时间源，便于测试会话过期。"""

from __future__ import annotations

import time
from collections.abc import Callable

TimeSource = Callable[[], float]


def system_time() -> float:
    return time.time()
