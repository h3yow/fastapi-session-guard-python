# fastapi-session-guard

基于 FastAPI 的本地可复现登录、多会话管理、会话续期与访问控制示例。内存存储、
无外部依赖服务，支持多客户端并发、令牌重放检测、按会话/按账号注销、活跃会话
上限淘汰，以及账号与权限变更的一致判定。

## 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/login` | 用户名+密码（可选 `source` 来源标识）登录，签发短期 access token 与单次 refresh token |
| POST | `/refresh` | 用 refresh token 轮换出新的令牌对 |
| GET | `/protected/sessions` | 查看当前账号所有仍有效会话（来源、签发时间、到期时间） |
| POST | `/protected/sessions/{session_id}/logout` | 注销指定会话 |
| POST | `/protected/sessions/logout-all` | 注销当前账号的全部会话 |
| GET | `/protected/profile` | 需要有效会话 |
| GET | `/protected/admin` | 需要有效会话且用户当前具备 `admin` 权限 |

会话管理接口与其他受保护接口一样，需要 `Authorization: Bearer <access_token>`；
操作者身份完全由该 token 决定，请求体中不接受用户名。

内置用户（仅本地演示）：`alice/alice-pass`（有 `admin` 权限）、
`bob/bob-pass`（无权限）、`carol/carol-pass`（已禁用）。

## 多会话与来源标识

- 同一账号可同时拥有多个互相独立的会话。登录时在 JSON 体中可选传入
  `source`（设备名/客户端名，如 `"iphone-15"`、`"chrome-on-mac"`），
  缺省为空字符串。`source` 只用于展示，不参与任何安全判定。
- 续期是**按会话**轮换：刷新会话 A 的令牌只替换 A 的 access/refresh token，
  同一账号的会话 B 完全不受影响（session_id 在轮换中保持不变，
  `source` 与原始签发时间也保留）。
- `GET /protected/sessions` 返回调用者**自己**的有效会话清单，按签发时间
  从旧到新排列，每条包含：

  ```json
  {
    "session_id": "...",
    "source": "iphone-15",
    "issued_at": 1791230000.0,
    "access_expires_at": 1791230300.0,
    "refresh_expires_at": 1791233600.0
  }
  ```

  已注销、已淘汰、已过 refresh TTL 的会话不出现在清单中。

### 注销规则

- **单个注销**：`POST /protected/sessions/{session_id}/logout`。注销立刻生效：
  该会话之后的访问返回 `session_revoked`，续期也返回 `session_revoked`；
  同账号的其他会话不受影响。
- **全部注销**：`POST /protected/sessions/logout-all`，撤销调用者账号当前全部
  有效会话，返回 `{"status":"revoked","revoked":N}`；**绝不波及其他账号**。
- **可见范围**：只能查看和操作自己的会话。对他人的 session_id 或不存在的
  session_id 执行注销，统一返回 `404 session_not_found`（响应完全一致，
  无法借此探测别人会话是否存在）。注销一个已经注销/失效的会话同样得到
  `session_not_found`。
- 注销全部会话后，发起注销所用的 access token 本身也随之失效（语义为
  "退出这个账号的所有登录"）。

### 注销与并发续期相遇

所有改写会话的操作（登录淘汰、续期、注销、全部注销）都在同一把存储锁内
完成，竞争结果确定、可复现。主动注销与同一会话正在进行的续期并发时：

- 若**注销先提交**：会话立即撤销，所有并发/之后的续期一律失败，绝无"注销后
  还能续期成功"的可能。
- 若**续期先提交**：恰好一个续期成功并轮换令牌，随后到达的注销会取到轮换后的
  会话并把它（含新令牌对）一并撤销；此时续期与注销各自返回一次成功，
  但终态与会话内容与"注销先提交"完全相同——会话彻底死亡，任何令牌都不可再用。
- 多个并发请求竞争同一 refresh token 的既有规则不变：恰好一个成功，其余
  `refresh_reused`，整个会话被撤销。

### 活跃会话上限与淘汰

- 每个账号的有效会话数有上限，默认 **5**，可通过
  `create_app(..., max_sessions_per_user=N)` 调整。
- 登录使会话数超过上限时，按确定规则淘汰：**淘汰剩余有效会话中
  `issued_at`（原始签发时间）最早的一条**；同一毫秒内签发的会话以
  `session_id` 字典序作为确定性平局规则。轮换令牌不会改变签发时间，
  所以一个老会话即使频繁续期，仍然比新会话先被淘汰。
- 已过 refresh TTL 的会话不算活跃、不占名额，因此不会触发淘汰。
- 淘汰按账号独立计算：A 账号超额不会淘汰到 B 账号的任何会话。
- 被淘汰会话之后的访问与续期稳定返回 `401 session_evicted`，该终态不会被
  后续操作覆盖（例如再发生 refresh 重放也仍然是 `session_evicted`），
  与 `session_revoked` / `session_expired` / `refresh_reused` 都可区分。
  淘汰发生时日志记录被淘汰的 `session_id`、签发时间与当时名额，可审计。

## 会话生命周期

1. **签发**：`POST /login` 成功后创建会话，返回 `access_token`（默认 300s）
   与 `refresh_token`（默认 3600s），二者绑定同一 `session_id`。
2. **访问**：受保护接口通过 `Authorization: Bearer <access_token>` 判定。
3. **续期**：`POST /refresh` 携带 refresh token，成功后**轮换**整对令牌
   （session_id 不变，旧 access/refresh token 立即失效）。
4. **失效**：会话被用户注销、因 refresh token 重放/并发复用被撤销、
   因超出活跃会话上限被淘汰，或超过 refresh TTL 后自然过期。

## 判定规则（可区分的拒绝原因）

拒绝响应体为 `{"detail": {"reason": ..., "request_id": ...}}`，`reason` 取值：

| reason | HTTP | 含义 |
| --- | --- | --- |
| `invalid_credentials` | 401 | 登录失败。用户不存在、密码错误、账号禁用**返回完全相同的响应**，不泄露账号是否存在 |
| `missing_session` | 401 | 未携带 Bearer token |
| `session_expired` | 401 | 令牌已过有效期（access 过期时 refresh 可能仍可用） |
| `session_revoked` | 401 | 会话已被用户注销，或 token 未知/已被轮换 |
| `refresh_reused` | 401 | refresh token 被重复使用（重放或并发竞争），整个会话已撤销 |
| `session_evicted` | 401 | 该会话被活跃会话上限淘汰，终态稳定且不被后续操作覆盖 |
| `account_disabled` | 401 | 账号当前处于停用状态（登录时停用仍统一为 `invalid_credentials`） |
| `forbidden` | 403 | 会话有效，但用户当前不具备所需权限 |
| `session_not_found` | 404 | 注销目标不存在、不属于当前用户，或已经失效（统一响应，无法探测他人会话） |

### 续期与重放规则（确定性）

- 每个 refresh token **只能成功使用一次**。
- 同一 refresh token 的任何第二次使用——无论是旧令牌重放，还是并发请求
  竞争同一当前令牌——都会**撤销整个会话**：新旧 access/refresh token 全部失效。
- 并发 N 个相同 refresh 请求时，**恰好一个成功**，其余收到 `refresh_reused`，
  且会话被撤销（获胜方的令牌也随之失效）。该判定在存储层锁内完成，结果确定。
- 严格顺序的续期（每次用最新 refresh token）不会被误判。

### 账号状态与权限变更语义

账号是否停用、具备哪些权限，都在**每次请求时**根据用户的当前记录实时判定，
不缓存在会话中：

- 账号在后台被**停用**后，该用户**所有已存在的会话立即**失效——访问受保护
  接口（含会话清单/注销接口）返回 `account_disabled`，续期同样返回
  `account_disabled`，无需也无法重新登录；
- 账号随后**恢复启用**，其仍在有效期内的现有会话立刻恢复可用，无需重新登录；
- 权限被授予或撤销后，该用户所有已存在的会话立即按新权限判定。

状态变更只影响对应账号自己的会话；会话自身的有效性（过期/注销/淘汰）
与账号状态、权限判定相互独立，且各拒绝原因保持可区分。

### 可观测性

每次允许/拒绝都以 `session_guard` logger 打印日志，包含
`request_id`（取自 `X-Request-ID` 请求头，缺失时自动生成并回传于响应体）、
路径与判定依据，例如：

```
INFO:session_guard:deny request_id=req-acc-4 path=/protected/admin reason=forbidden detail=user=bob lacks permission=admin
INFO:session_guard:evict user=alice session_id=7LwQNAq... reason=session_evicted active=6 cap=5
INFO:session_guard:revoke user=alice session_id=... reason=session_revoked detail=user logout
```

## 本地验证

```bash
# 安装依赖（uv）
uv sync

# 运行测试（含并发续期、注销竞争、重放、过期、淘汰、账号状态、权限不足等边界场景）
uv run pytest -q
# 查看测试日志中的请求标识与判定依据
uv run pytest -o log_cli=true

# 启动服务并手动验证
uv run python main.py   # http://127.0.0.1:8000/docs

# 1) 两个客户端分别登录（带来源标识），各得一份令牌
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice-pass","source":"phone"}'
curl -s -X POST localhost:8000/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice-pass","source":"laptop"}'

# 2) 查看自己的有效会话清单（用任一有效 access token）
curl -s localhost:8000/protected/sessions -H "Authorization: Bearer <access_token>"

# 3) 注销指定会话（不影响同账号其他会话）
curl -s -X POST localhost:8000/protected/sessions/<session_id>/logout \
  -H "Authorization: Bearer <access_token>"

# 4) 一次性注销本账号全部会话
curl -s -X POST localhost:8000/protected/sessions/logout-all \
  -H "Authorization: Bearer <access_token>"
```

## 结构

```
app/
  models.py   # 类型定义：User / Session（source/issued_at/evicted）/ TokenPair / DenyReason
  store.py    # 带锁的内存用户/会话存储（按账号索引、已轮换 refresh token 登记表）
  auth.py     # 登录（来源标识+上限淘汰）、轮换、重放检测、清单、注销、撤销
  deps.py     # FastAPI 依赖：会话解析（含淘汰/停用实时判定）、权限检查、拒绝日志
  routes.py   # HTTP 路由（登录/续期/会话清单/单个注销/全部注销）
main.py       # 应用组装、内置用户与 max_sessions_per_user 配置
tests/        # pytest：多会话隔离、清单范围、注销、并发竞争、淘汰、账号状态；
              #         以及登录、续期、重放、过期、权限的无回归用例
```
