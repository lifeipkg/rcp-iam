# rcp-iam · 身份与访问管理（Go）

平台**唯一**的 IAM 服务，Go + Gin 实现：登录、会话、令牌内省、角色授予。
服务名 `iam`，端口 `8085`，契约 `rcp-contracts/contracts/openapi/iam.yaml`，
只经 `api-gateway` 的 `/api/v1/iam/**` 透传访问（`external=false`，RL-002）。
早期 Java 版实现已退役，本仓顶替其身份与鉴权链。

## 在鉴权链里的位置

```
前端 /api  ──>  api-gateway  ──/api/v1/iam/** 透传──>  rcp-iam
                    │
                    └── 每个受保护请求 ──/api/v1/iam/introspect──> rcp-iam
```

网关逐请求内省**只走本服务**：令牌无效 → 401，缺权限 → 403，本服务不可达 → 503
（fail closed，绝不降级放行）。网关只判「这条路由需要哪个 permission」，不解析令牌、
不存角色表。角色→权限展开只在 `internal/service/auth.go` 一处。

## 数据链路（RL-005）

```
iam  --只读 SELECT-->  dataway /dataway/query  --org.postgresql--> PostgreSQL
     --模板 ID 写入-->  dataway /dataway/execute --pgx/v5--> PostgreSQL
```

- 表 `iam_users` / `iam_sessions` 的 DDL 只在 `rcp-ops/migrations/V1.4.0__iam_store.sql`（RL-004）。
- `dataway` 的表白名单与 6 个写入模板登记在 `rcp-dataway/internal/config/dataway.yaml`：
  `iam.user.insert` / `iam.user.update` / `iam.session.insert` / `iam.session.delete` /
  `iam.session.deleteByUser` / `iam.session.cleanExpired`。
- 会话过期判定下推到 SQL（`s.expires_at > CURRENT_TIMESTAMP`），避免跨库时间格式解析；
  停用账号的令牌同时由 `u.status = 'ACTIVE'` 与「停用时吊销会话」双重拦住。
- `dataway` 不可用 → `ErrUnavailable` → HTTP 503，**不降级放行**。
- 会话与用户都在 PostgreSQL，不在实例内存，故可多副本；当前仍按 1 副本部署。

## 角色与权限

`ADMIN` → `patrol:dispatch`, `iam:users`；`OPERATOR` → `patrol:dispatch`；`VIEWER` → 无。

## 接口

```
POST   /api/v1/iam/login
POST   /api/v1/iam/logout
POST   /api/v1/iam/introspect
GET    /api/v1/iam/me
GET    /api/v1/iam/users
POST   /api/v1/iam/users
PUT    /api/v1/iam/users/{userId}
PUT    /api/v1/iam/users/{userId}/password
GET    /actuator/health               # 运维探活，不在公开契约内
```

请求/响应字段以契约仓为准，本仓不得自行改动。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SERVER_PORT` | `8085` | 监听端口 |
| `DATAWAY_HOST` | `localhost` | 数据网关服务名（K8s/compose 注入 `dataway`，按名解析，RL-007） |
| `DATAWAY_PORT` | `8090` | 数据网关端口 |
| `DATAWAY_DATASOURCE` | `main` | 数据源名（连接串由 dataway 持有） |
| `IAM_TOKEN_TTL_HOURS` | `8` | 令牌有效期 |
| `IAM_PBKDF2_ITER` | `120000` | 口令派生迭代数 |
| `IAM_ADMIN_PASSWORD` 等 | 演示口令 | **部署必须覆盖**，经 `rcp-iam-bootstrap` Secret 注入 |

启动按「用户不存在才创建」写入 `admin` / `operator` / `viewer`；初始化失败即退出，
不带空用户表对外提供鉴权。

## 构建与验证

```bash
go mod tidy && go vet ./... && go test ./... && go build ./...
python ../rcp-contracts/tools/contract_check.py --repo . \
  --contract ../rcp-contracts/contracts/openapi/iam.yaml
docker build -t rcp-iam:local .
```

测试含反向用例：错误口令、停用账号、越权、令牌吊销后复用、改密后旧会话失效、
dataway 不可用 fail closed。

## 已知边界

- `go.sum` 由首次 `go mod tidy` 生成并入库；当前开发环境没有 Go 工具链，未手抄模块哈希。
- 远程为 `lifeipkg/rcp-iam`（公开）。合并 main / push 按工作区规则须逐次取得人类明确授权。
- K8s 侧数据库为外部依赖，需集群提供名为 `postgres` 的 Service 与
  `rcp-db-credential` Secret；`rcp-ops/k8s` 只提供连接串。
- 用户名唯一由应用层先查再插，未用数据库唯一约束做并发兜底（演示定位）。
- 探活只有 `/actuator/health`，K8s 的 readiness / liveness 都指向它；没有 Java
  Actuator 的 `/readiness` `/liveness` 子路径。
