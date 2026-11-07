package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/lifeipkg/rcp-iam-go/internal/config"
	"github.com/lifeipkg/rcp-iam-go/internal/service"
	"github.com/lifeipkg/rcp-iam-go/internal/store"
	"github.com/lifeipkg/rcp-iam-go/internal/web"
)

func main() {
	cfg := config.Load()
	// 生产唯一实现是 dataway 的 HTTP 客户端；本仓不连 PostgreSQL、不持驱动（RL-005）。
	st := store.NewDataway(cfg.DatawayURL, cfg.Datasource)
	auth := service.New(st, cfg.TokenTTL, cfg.PBKDF2Iter)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := auth.Bootstrap(ctx, cfg.BootstrapUsers); err != nil {
		// dataway 不可用时宁可不启动，也不带着空用户表对外提供鉴权（不制造半激活）。
		log.Fatalf("引导账号初始化失败: %v", err)
	}

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           web.NewRouter(auth),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("iam-go listening on :%s, dataway=%s", cfg.Port, cfg.DatawayURL)
	log.Fatal(srv.ListenAndServe())
}
