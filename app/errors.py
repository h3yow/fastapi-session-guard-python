"""统一的认证/授权错误类型与错误码。

对外拒绝结果通过 code 区分；登录场景由路由层统一折叠为不可区分的原因。
"""


class AuthError(Exception):
    """可对外解释的认证/授权异常。"""

    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


# 错误码常量（可区分的拒绝结果）
LOGIN_INVALID = "invalid_credentials"  # 401 登录：账号不存在/禁用/口令错误，对外不可区分
SESSION_MISSING = "session_missing"  # 401 访问：无会话凭证
SESSION_INVALID = "session_invalid"  # 401 访问：凭证无法识别
SESSION_REVOKED = "session_revoked"  # 401 访问/续期：会话已被整体吊销（含重放触发）
SESSION_EXPIRED = "session_expired"  # 401 访问/续期：会话已过期
REFRESH_INVALID = "refresh_invalid"  # 401 续期：续期凭证无法识别
ACCOUNT_DISABLED = "account_disabled"  # 403 访问：账号已被禁用（登录时折叠为 invalid_credentials）
PERMISSION_DENIED = "permission_denied"  # 403 访问：权限不足
USER_NOT_FOUND = "user_not_found"  # 404 管理接口：目标用户不存在
