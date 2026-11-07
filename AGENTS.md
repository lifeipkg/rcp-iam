# AGENTS.md · rcp-iam-go

本仓规则。工作区级流程见 `<工作区根>/AGENTS.md`；契约见 `../rcp-contracts`。

## 本仓是什么

Go + Gin 版身份与访问管理服务（服务名 `iam-go`，端口 `8086`）：登录、会话、令牌内省、
角色授予。与 Java 版 `iam`（8085）**并行存在**，用于 Go 技术栈的独立验收；网关的逐请求
内省仍走 `iam`，本服务不接管鉴权链。改动按标准轨处理，命中公开契约或鉴权语义须独立复核。

| 项 | 值 |
|---|---|
| 服务名 / 端口 | `iam-go` / `8086` |
| 契约 | `rcp-contracts/contracts/openapi/iam-go.yaml` |
| 路由前缀 | `/api/v1/iam-go/**` |
| 上游 | `api-gateway`（透传）；`dataway`（数据面，8090） |
| 存储 | PostgreSQL，经 `dataway` 的 HTTP 契约读写 |

## 硬约束

1. **不直连数据库**（RL-005）。本仓 `go.mod` 只有 `gin`，不得出现 `pgx` / `lib/pq` /
   `database/sql` 的驱动依赖；只读走 `POST /dataway/query`（单条 SELECT、白名单表），
   写入走 `POST /dataway/execute`（服务端模板 ID）。模板登记在 `rcp-dataway` 的
   `application.yml`，表结构在 `rcp-ops/migrations/V1.4.0`（RL-004，本仓不建表）。
2. **只被网关调用**。`external=false`；控制器路径与请求响应字段以契约仓为准，
   改字段先改契约再抬钉，禁止先改实现。
3. **路由写成完整字面量**。`rcp-contracts/tools/contract_check.py` 用正则抽
   `r.GET/r.POST/r.PUT(...)` 与 OpenAPI 做两向差集，变量拼接会让机械对表失效；
   运维探活 `/actuator/health` 用 `r.Handle` 注册，不计入契约路由。
4. **令牌语义只在本仓**。不透明 Bearer 令牌、有效期、角色→权限展开只在
   `internal/service`；下游只调 `/introspect`，不得复制角色表或解析令牌。
5. **鉴权 fail closed**。`dataway` 不可用一律 503，不回落匿名、不降级到内存存储；
   `MemoryStore` 只供单元测试使用，生产 `main` 只装配 `DatawayStore`。
6. **口令材料不出仓**。PBKDF2-HmacSHA256 + 每用户随机盐只在 `internal/service` 实现；
   响应视图不含哈希与盐，日志不打印口令与令牌。
7. **不制造半激活**：引导账号初始化失败时服务不启动。

## 验证

```bash
go mod tidy && go vet ./... && go test ./... && go build ./...
python ../rcp-contracts/tools/contract_check.py --repo . \
  --contract ../rcp-contracts/contracts/openapi/iam-go.yaml
```

改鉴权或口令逻辑必须补反向用例：错误口令、停用账号、越权、令牌吊销后复用、
改密后旧会话失效，至少覆盖与本次改动相关的项。
