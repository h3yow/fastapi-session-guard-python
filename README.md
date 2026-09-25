# fastapi-session-guard

基于 FastAPI 的本地可复现登录、会话续期与访问控制示例。内存存储、无外部依赖服务，
支持多客户端并发、令牌重放检测与权限变更的一致判定。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/login` | 用户名+密码登录，签发短期 access token 与单次 refresh token |
| POST | `/refresh` | 用 refresh token 轮换出新的令牌对 |
| GET | `/protected/profile` | 需要有效会话 |
| GET | `/protected/admin` | 需要有效会话且用户当前具备 `admin` 权限 |

内置用户（仅本地演示）：`alice/alice-pass`（有 `admin` 权限）、
`bob/bob-pass`（无权限）、`carol/carol-pass`（已禁用）。

## 会话生命周期

1. **签发**：`POST /login` 成功后创建会话，返回 `access_token`（默认 300s）
   与 `refresh_token`（默认 3600s），二者绑定同一 `session_id`。
2. **访问**：受保护接口通过 `Authorization: Bearer <access_token>` 判定。
3. **续期**：`POST /refresh` 携带 refresh token，成功后**轮换**整对令牌
   （session_id 不变，旧 access/refresh token 立即失效）。
4. **失效**：会话因 refresh token 重放/并发复用被撤销，或超过 refresh TTL 后自然过期。

## 判定规则（可区分的拒绝原因）

拒绝响应体为 `{"detail": {"reason": ..., "request_id": ...}}`，`reason` 取值：

| reason | HTTP | 含义 |
| --- | --- | --- |
| `invalid_credentials` | 401 | 登录失败。用户不存在、密码错误、账号禁用**返回完全相同的响应**，不泄露账号是否存在 |
| `missing_session` | 401 | 未携带 Bearer token |
| `session_expired` | 401 | 令牌已过有效期（access 过期时 refresh 可能仍可用） |
| `session_revoked` | 401 | 会话已被撤销，或 token 未知/已被轮换 |
| `refresh_reused` | 401 | refresh token 被重复使用（重放或并发竞争） |
| `forbidden` | 403 | 会话有效，但用户当前不具备所需权限 |

### 续期与重放规则（确定性）

- 每个 refresh token **只能成功使用一次**。
- 同一 refresh token 的任何第二次使用——无论是旧令牌重放，还是并发请求
  竞争同一当前令牌——都会**撤销整个会话**：新旧 access/refresh token 全部失效。
- 并发 N 个相同 refresh 请求时，**恰好一个成功**，其余收到 `refresh_reused`，
  且会话被撤销（获胜方的令牌也随之失效）。该判定在存储层锁内完成，结果确定。
- 严格顺序的续期（每次用最新 refresh token）不会被误判。

### 权限变更语义

权限在**每次请求时**根据用户的当前记录实时判定，不缓存在会话中：
权限被授予或撤销后，该用户**所有已存在的会话立即**按新权限生效，
无需重新登录。会话自身的有效性（过期/撤销）与权限判定相互独立。

### 可观测性

每次允许/拒绝都以 `session_guard` logger 打印日志，包含
`request_id`（取自 `X-Request-ID` 请求头，缺失时自动生成并回传于响应体）、
路径与判定依据，例如：

```
INFO:session_guard:deny request_id=req-acc-4 path=/protected/admin reason=forbidden detail=user=bob lacks permission=admin
```

## 本地验证

```bash
# 安装依赖（uv）
uv sync

# 运行测试（含并发续期、重放、过期、权限不足等边界场景）
uv run pytest -q
# 查看测试日志中的请求标识与判定依据
uv run pytest -o log_cli=true

# 启动服务并手动验证
uv run python main.py   # http://127.0.0.1:8000/docs

curl -s -X POST localhost:8000/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'
```

## 结构

```
app/
  models.py   # 类型定义：User / Session / TokenPair / DenyReason
  store.py    # 带锁的内存用户/会话存储（含已轮换 refresh token 登记表）
  auth.py     # 登录、签发、轮换、重放检测与撤销
  deps.py     # FastAPI 依赖：会话解析、权限检查、拒绝日志
  routes.py   # HTTP 路由
main.py       # 应用组装与内置用户
tests/        # pytest：登录不可区分、轮换、重放、并发、过期、权限变更
```
