FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
# 首次构建由 go mod tidy 生成 go.sum 并补全模块图（本机无 Go 工具链时不手抄哈希）
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/iam-go .

FROM alpine:3.20
RUN adduser -D -u 10001 app
COPY --from=build /out/iam-go /app/iam-go
USER app
EXPOSE 8086
ENV SERVER_PORT=8086
ENTRYPOINT ["/app/iam-go"]
