# fastapi-session-guard

基于 FastAPI 的本地可复现登录、会话续期与访问控制示例。内存存储、无外部依赖服务，
支持多客户端并发、令牌重放检测、权限变更的一致判定，以及多会话管理
（会话清单、按会话/全量注销、每账号会话上限与确定性淘汰）。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/login` | 用户名+密码登录，可带 `source` 来源标识；签发短期 access token 与单次 refresh token |
| POST | `/refresh` | 用 refresh token 轮换出新的令牌对 |
| GET | `/sessions` | 列出**当前账号**所有仍有效的会话（来源、签发时间、到期时间） |
| DELETE | `/sessions/{session_id}` | 注销当前账号的某一个会话，立即生效 |
| DELETE | `/sessions` | 注销当前账号的全部会话（含本次请求所用会话） |
| GET | `/protected/profile` | 需要有效会话 |
| GET | `/protected/admin` | 需要有效会话且用户当前具备 `admin` 权限 |

内置用户（仅本地演示）：`alice/alice-pass`（有 `admin` 权限）、
`bob/bob-pass`（无权限）、`carol/carol-pass`（已禁用）。

## 会话生命周期

1. **签发**：`POST /login` 成功后创建会话，返回 `access_token`（默认 300s）
   与 `refresh_token`（默认 3600s），二者绑定同一 `session_id`。
   请求体可带可选字段 `source`（设备名/客户端名），会记入会话并展示在清单里。
2. **访问**：受保护接口通过 `Authorization: Bearer <access_token>` 判定。
3. **续期**：`POST /refresh` 携带 refresh token，成功后**轮换**整对令牌
   （session_id、source、签发时间不变，旧 access/refresh token 立即失效）。
4. **失效**：会话因注销、refresh token 重放/并发复用被撤销、超出每账号上限被淘汰，
   或超过 refresh TTL 后自然过期。

## 多会话与来源标识

- 同一账号可同时持有多个会话（例如 `source: "laptop"` 与 `source: "phone"` 各登录一次），
  每个会话有独立的 `session_id` 与令牌对。
- 会话之间完全隔离：对其中一个会话续期（轮换令牌）或注销，不影响同账号的其他会话。
- `GET /sessions` 只返回**当前账号**的仍有效会话（未撤销、未过 refresh 期），
  每条包含 `session_id`、`source`、`issued_at`、`access_expires_at`、`refresh_expires_at`，
  并用 `current: true` 标出本次请求所用的会话。看不到、也操作不了别人的会话。

## 注销规则

- `DELETE /sessions/{session_id}`：注销自己的一个会话，立即生效——
  该会话的 access 与 refresh 此后都失败（`session_revoked`），并从清单中消失。
  注销他人的会话与注销不存在的会话**返回完全相同的** `404 session_not_found`，
  不泄露会话是否存在。
- `DELETE /sessions`：注销本账号全部会话（返回 `revoked_count`），不影响其他账号。
- **注销与并发续期竞争**：注销和续期都在同一把存储锁内串行执行，因此只会出现两种
  确定结果之一——续期先完成则注销随后撤销轮换后的新令牌；注销先完成则续期得到
  `session_revoked`。无论哪种顺序，最终状态一致：该会话被撤销，**之后任何续期
  都不会再成功**，也不会出现半轮换的中间状态。

## 每账号活跃会话上限与淘汰规则

- 每个账号最多同时持有 **5 个**活跃会话（`create_app(max_sessions=...)` 可调）。
  “活跃”指未撤销且 refresh 未过期。
- 第 N+1 次登录成功签发新会话后，按**签发顺序淘汰最旧的会话**
  （以单调序号 `issued_seq` 判定，续期不改变序号，因此同时间登录也有确定顺序）；
  刚签发的会话永远不会被当次淘汰。
- 被淘汰会话之后的请求得到稳定、可区分的拒绝：访问与续期都返回
  `401 session_evicted`，与主动注销的 `session_revoked` 可区分。
- 上限按账号独立计算，一个账号被淘汰不影响其他账号。

## 账号状态变化的生效范围

- 账号被停用（`UserStore.set_disabled(username, True)`）后，该账号**所有已存在会话**
  的访问与续期立即失败（`401 account_disabled`），无需等会话过期；登录仍返回
  与其他失败完全相同的 `invalid_credentials`。
- 账号恢复后，既有会话**无需重新登录**即可继续使用（状态在每次请求时实时检查，
  不缓存在会话中）。停用/恢复不影响其他账号。

## 判定规则（可区分的拒绝原因）

拒绝响应体为 `{"detail": {"reason": ..., "request_id": ...}}`，`reason` 取值：

| reason | HTTP | 含义 |
| --- | --- | --- |
| `invalid_credentials` | 401 | 登录失败。用户不存在、密码错误、账号禁用**返回完全相同的响应**，不泄露账号是否存在 |
| `missing_session` | 401 | 未携带 Bearer token |
| `session_expired` | 401 | 令牌已过有效期（access 过期时 refresh 可能仍可用） |
| `session_revoked` | 401 | 会话已被撤销（注销或重放），或 token 未知/已被轮换 |
| `session_evicted` | 401 | 会话因超出每账号上限被淘汰（最旧者出局） |
| `refresh_reused` | 401 | refresh token 被重复使用（重放或并发竞争） |
| `account_disabled` | 401 | 会话签发后账号被停用；恢复后同一会话可继续使用 |
| `session_not_found` | 404 | 注销目标不存在或属于其他账号（两者不可区分） |
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
无需重新登录。会话自身的有效性（过期/撤销/淘汰）与权限判定相互独立。

### 可观测性

每次允许/拒绝都以 `session_guard` logger 打印日志，包含
`request_id`（取自 `X-Request-ID` 请求头，缺失时自动生成并回传于响应体）、
路径与判定依据，例如：

```
INFO:session_guard:deny request_id=req-acc-4 path=/protected/admin reason=forbidden detail=user=bob lacks permission=admin
INFO:session_guard:logout request_id=req-lo-3 user=alice session_id=WmQzqX2tw7sh0gFSEIxLNA
```

## 本地验证

```bash
# 安装依赖（uv）
uv sync

# 运行测试（含并发续期、重放、过期、权限、多会话、注销竞争、淘汰、账号状态等场景）
uv run pytest -q
# 查看测试日志中的请求标识与判定依据
uv run pytest -o log_cli=true

# 启动服务并手动验证
uv run python main.py   # http://127.0.0.1:8000/docs

# 多会话：分别带来源标识登录两次
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice-pass","source":"laptop"}'
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice-pass","source":"phone"}'

# 查看自己的会话清单（用任意一个会话的 access_token）
curl -s localhost:8000/sessions -H "Authorization: Bearer <access_token>"

# 注销单个会话 / 注销全部会话
curl -s -X DELETE localhost:8000/sessions/<session_id> \
  -H "Authorization: Bearer <access_token>"
curl -s -X DELETE localhost:8000/sessions \
  -H "Authorization: Bearer <access_token>"
```

## 结构

```
app/
  models.py   # 类型定义：User / Session / SessionInfo / TokenPair / DenyReason
  store.py    # 带锁的内存用户/会话存储（含已轮换 refresh token 登记表）
  auth.py     # 登录、签发、轮换、重放检测、注销、上限淘汰与账号状态检查
  deps.py     # FastAPI 依赖：会话解析、权限检查、拒绝日志
  routes.py   # HTTP 路由（登录/续期/会话清单/注销/受保护资源）
main.py       # 应用组装与内置用户
tests/        # pytest：登录不可区分、轮换、重放、并发、过期、权限变更、
              #         多会话隔离、清单可见范围、注销、注销竞争、淘汰、账号状态
```
