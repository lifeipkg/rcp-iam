# rcp-iam-go · Go 版身份与访问管理

Go + Gin 实现的 IAM：登录、会话、令牌内省、角色授予。服务名 `iam-go`，端口 `8086`，
契约 `rcp-contracts/contracts/openapi/iam-go.yaml`，只经 `api-gateway` 的
`/api/v1/iam-go/**` 透传访问（`external=false`，RL-002）。

## 与 Java 版 iam 的关系

| | `iam`（Java） | `iam-go`（Go） |
|---|---|---|
| 端口 / 前缀 | 8085 / `/api/v1/iam/**` | 8086 / `/api/v1/iam-go/**` |
| 网关逐请求内省 | 是（鉴权链） | 否，并行验收用 |
| 存储 | 进程内 Map | PostgreSQL，经 `dataway` HTTP 契约 |

两者并存，网关的鉴权链仍指向 `iam`；把鉴权迁到 `iam-go` 属独立变更，需另改网关、
契约、本体登记与逐次发布授权，不在本版范围内。

## 数据链路（RL-005）

```
iam-go  --只读 SELECT-->  dataway /dataway/query  --org.postgresql--> PostgreSQL
        --模板 ID 写入-->  dataway /dataway/execute --org.postgresql--> PostgreSQL
```

- 表 `iam_users` / `iam_sessions` 的 DDL 只在 `rcp-ops/migrations/V1.4.0__iam_go_store.sql`（RL-004）。
- `dataway` 的表白名单与 6 个写入模板登记在 `rcp-dataway/src/main/resources/application.yml`：
  `iam.user.insert` / `iam.user.update` / `iam.session.insert` / `iam.session.delete` /
  `iam.session.deleteByUser` / `iam.session.cleanExpired`。
- 会话过期判定下推到 SQL（`s.expires_at > CURRENT_TIMESTAMP`），避免跨库时间格式解析；
  停用账号的令牌同时由 `u.status = 'ACTIVE'` 与「停用时吊销会话」双重拦住。
- `dataway` 不可用 → `ErrUnavailable` → HTTP 503，**不降级放行**。

## 角色与权限

`ADMIN` → `patrol:dispatch`, `iam:users`；`OPERATOR` → `patrol:dispatch`；`VIEWER` → 无。
权限展开只在 `internal/service/auth.go` 一处，网关与其他服务不复制这张表。

## 接口

```
POST   /api/v1/iam-go/login
POST   /api/v1/iam-go/logout
POST   /api/v1/iam-go/introspect
GET    /api/v1/iam-go/me
GET    /api/v1/iam-go/users
POST   /api/v1/iam-go/users
PUT    /api/v1/iam-go/users/{userId}
PUT    /api/v1/iam-go/users/{userId}/password
GET    /actuator/health               # 运维探活，不在公开契约内
```

请求/响应字段以契约仓为准，本仓不得自行改动。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SERVER_PORT` | `8086` | 监听端口 |
| `DATAWAY_HOST` | `localhost` | 数据网关服务名（K8s/compose 注入 `dataway`，按名解析，RL-007） |
| `DATAWAY_PORT` | `8090` | 数据网关端口 |
| `DATAWAY_DATASOURCE` | `main` | 数据源名（连接串由 dataway 持有） |
| `IAM_GO_TOKEN_TTL_HOURS` | `8` | 令牌有效期 |
| `IAM_GO_PBKDF2_ITER` | `120000` | 口令派生迭代数 |
| `IAM_GO_ADMIN_PASSWORD` 等 | 演示口令 | **部署必须覆盖** |

启动按「用户不存在才创建」写入 `admin` / `operator` / `viewer`；初始化失败即退出，
不带空用户表对外提供鉴权。

## 构建与验证

```bash
go mod tidy && go vet ./... && go test ./... && go build ./...
python ../rcp-contracts/tools/contract_check.py --repo . \
  --contract ../rcp-contracts/contracts/openapi/iam-go.yaml
docker build -t rcp-iam-go:local .
```

测试含反向用例：错误口令、停用账号、越权、令牌吊销后复用、改密后旧会话失效、
dataway 不可用 fail closed。

## 已知边界

- `go.sum` 由首次 `go mod tidy` 生成并入库；当前开发环境没有 Go 工具链，未手抄模块哈希。
- 本仓无远程（`lifeipkg/rcp-iam-go` 未创建）；推送前需先建远程，且合并 main / push
  按工作区规则须逐次取得人类明确授权。
- K8s 侧数据库为外部依赖，需集群提供名为 `postgres` 的 Service 与
  `rcp-db-credential` Secret；`rcp-ops/k8s` 只提供连接串。
- 用户名唯一由应用层先查再插，未用数据库唯一约束做并发兜底（演示定位）。
