# Local Session Guard（FastAPI）

一套**纯本地、可复现**的登录 / 会话续期 / 访问控制服务。无外部数据库依赖，
用户资料与会话保存在进程内存中，目标是让「多客户端并发、令牌重放、权限
变更」三类场景得到一致且可解释的判定结果。

## 1. 快速开始

```bash
uv sync --group dev

# 启动服务（默认 127.0.0.1:8000，内置演示用户）
uv run uvicorn main:app --reload

# 运行全部测试（含并发、重放、过期、权限变更边界）
uv run pytest -v
```

启动后可访问交互式文档：<http://127.0.0.1:8000/docs>

### 内置演示用户

| 用户名 | 口令 | 角色 | 状态 |
| --- | --- | --- | --- |
| `alice` | `alice-pass-123` | `view`, `admin` | 正常 |
| `bob`   | `bob-pass-123`   | `view` | 正常 |
| `carol` | `carol-pass-123` | `view` | **已禁用** |

## 2. 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/auth/login` | 本地资料登录，签发访问凭证 + 续期凭证 |
| POST | `/auth/refresh` | 用续期凭证换发新一代凭证对 |
| POST | `/auth/logout` | 主动吊销当前会话 |
| GET  | `/protected/whoami` | 需 `view`：回显当前资料与资料版本 |
| GET  | `/protected/view` | 需 `view` |
| GET  | `/protected/admin` | 需 `admin` |
| POST | `/admin/users/{u}/roles` | 需 `admin`：变更角色（立即生效） |
| POST | `/admin/users/{u}/disable` `/enable` | 需 `admin`：禁用/启用账号 |
| GET  | `/health` | 健康检查 |

所有响应均带 `X-Request-ID` 响应头；也可在请求中传入 `X-Request-ID`
做跨系统关联。每个错误体形如：

```json
{ "code": "session_expired", "message": "access token expired", "request_id": "…" }
```

## 3. 会话生命周期

```
登录成功
  │  生成会话 session_id（绝对寿命 session_ttl）
  │  下发 access_token（access_ttl，默认 300s）
  │  下发 refresh_token（refresh_ttl，默认 3600s，且不超过会话绝对寿命）
  ▼
正常使用 ──access 过期──► 用当前 refresh 调用 /auth/refresh
  │                         │ 旧 refresh 立即作废，换发新一代凭证对
  │                         ▼
  │                      继续使用（access 也可继续用到自身过期）
  ▼
以下任一情况使会话/凭证失效：
  • 会话绝对寿命到期（session_ttl）→ session_expired
  • 当前续期凭证过期（refresh_ttl）→ session_expired
  • 主动 /auth/logout            → session_revoked
  • 续期凭证被重放/并发复用        → session_revoked（整个会话）
```

默认 TTL 定义在 `app/config.py`，可通过 `Settings(access_ttl=...,
refresh_ttl=..., session_ttl=...)` 覆盖；测试中使用 10s/60s/600s 的短
TTL 并配合可手动推进的假时钟，**无需真实等待**即可复现过期。

凭证为高熵不透明随机串，服务端只存其 SHA-256 哈希；口令使用
PBKDF2-HMAC-SHA256（20 万轮）加盐存储。

## 4. 续期并发与重放规则（确定性）

核心实现在 `app/auth.py::AuthService.refresh`，规则如下：

1. 同一张续期凭证（按哈希标识）在会话**整个生命周期内最多成功一次**。
2. 「比对当前凭证 → 作废旧凭证 → 换发新一代 → 登记旧凭证」在
   `SessionStore` 的同一把锁内原子完成。
3. 凡出示**已轮换掉的旧凭证**——无论是并发争抢的落败者还是事后重放——
   立即**吊销整个会话**，返回 `401 session_revoked`，日志中带
   `reason=refresh_token_replay whole_session_revoked=true`。
4. 因此并发使用同一张续期凭证时：**恰有一次成功**；落败请求触发吊销后，
   就连唯一一次成功换发出的新凭证也立即不可用。
5. 按顺序正常续期（始终使用最新一代凭证）不会被误判；不同会话的并发
   续期互不影响。
6. 从未签发过的凭证返回 `401 refresh_invalid`，不泄露任何会话信息，
   也不牵连其他会话——与重放的 `session_revoked` 明确可区分。

确定性由内存锁保证（进程内）；`tests/test_threadpool.py` 以 8 线程 × 20
轮重复验证「恰一个赢家、其余全部 revoked、赢家新凭证同样失效」。

## 5. 访问判定与可区分拒绝码

`AuthService.authorize` 按固定顺序判定，拒绝码彼此可区分：

| 场景 | HTTP | `code` |
| --- | --- | --- |
| 未携带凭证 / 凭证头格式不对 | 401 | `session_missing` |
| 凭证无法识别 | 401 | `session_invalid` |
| 会话已被吊销（登出、重放等） | 401 | `session_revoked` |
| 访问凭证过期 / 会话绝对寿命到期 | 401 | `session_expired` |
| 账号已被禁用（对已有会话） | 403 | `account_disabled` |
| 角色不足 | 403 | `permission_denied` |
| 登录：账号不存在 / 禁用 / 口令错误 | 401 | `invalid_credentials`（三者不可区分） |

登录失败统一文案、统一错误码，响应不回显用户名；账号不存在时仍执行一次
完整口令推导，避免通过响应时间差异探测账号是否存在。

## 6. 权限变更的语义

* 会话**不保存权限快照**：每次受保护请求都实时读取本地用户资料
  （角色集合、禁用标志、资料版本 `version`）。
* 角色被授予 → 已有会话在**下一次请求**立即获得新范围，无需重新登录。
* 角色被收回 / 账号被禁用 → 已有会话在**下一次请求**立即失去相应范围
  （分别得到 `permission_denied` / `account_disabled`）。
* 已签发的访问凭证本身仍有效到其短 TTL 结束，但能否访问资源始终以最新
  资料为准——即「凭证有效 ≠ 仍有权限」。
* 管理接口的每次变更都会令资料 `version` 自增；`/protected/whoami`
  回显该版本，便于观察变更何时被会话观察到。

## 7. 日志与可解释性

业务 logger 名为 `session_guard`，每条判定日志都带 `request_id`：

```
INFO [request_id=ab12…] session_guard: auth decision: access rejected
     code=permission_denied session_id=… user=bob
WARN [request_id=cd34…] session_guard: auth decision: refresh rejected
     code=session_revoked session_id=… reason=refresh_token_replay
     whole_session_revoked=true
```

测试通过 `caplog` 断言「同一条日志上同时存在请求标识与判定依据
（错误码/原因）」，`uv run pytest -v` 时可直接在输出中看到这些日志。

## 8. 手工本地复现示例

```bash
# 1) 登录
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass-123"}'

# 2) 携带 access_token 访问管理员资源
curl -s localhost:8000/protected/admin -H "Authorization: Bearer <access_token>"

# 3) 续期（记录返回的新 refresh_token，旧的立即失效）
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' -d '{"refresh_token":"<refresh_token>"}'

# 4) 再拿旧 refresh_token 请求一次 -> 401 session_revoked，整个会话作废
# 5) bob 登录访问 /protected/admin -> 403 permission_denied
```

## 9. 测试覆盖

| 文件 | 覆盖内容 |
| --- | --- |
| `tests/test_login.py` | 登录成功；三类失败不可区分；判定日志 |
| `tests/test_refresh.py` | 顺序轮换、旧凭证重放吊销全会话、未知凭证、重放日志 |
| `tests/test_concurrent.py` | asyncio 并发争抢、混合重放、多会话互不干扰 |
| `tests/test_threadpool.py` | 真实线程并发（8×20 轮）确定性、跨会话独立性 |
| `tests/test_protected.py` | 缺失/无效/吊销/过期/权限不足可区分；授权扩缩；禁用；登出 |

## 10. 设计边界

* 会话存储是**进程内内存**实现，重启即失效；确定性保证的作用域为单进程。
  多进程部署需把 `SessionStore` 换成共享存储（如 Redis + Lua），保持
  「比对-换发-登记」原子性，判定规则不变。
* 演示用户仅用于本地复现，生产应替换用户来源与传输保护（HTTPS）。
