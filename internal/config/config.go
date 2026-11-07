package config

import (
	"os"
	"strconv"
	"time"
)

// Config 只从环境变量取值；仓内不落任何凭据。
type Config struct {
	Port           string
	DatawayURL     string
	Datasource     string
	TokenTTL       time.Duration
	PBKDF2Iter     int
	BootstrapUsers map[string]string
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func Load() Config {
	ttlHours, err := strconv.Atoi(env("IAM_TOKEN_TTL_HOURS", "8"))
	if err != nil || ttlHours <= 0 {
		ttlHours = 8
	}
	iter, err := strconv.Atoi(env("IAM_PBKDF2_ITER", "120000"))
	if err != nil || iter < 10000 {
		iter = 120000
	}
	// 按服务名解析：部署侧只注入 DATAWAY_HOST（K8s/compose Service 名）与端口，
	// 清单里不出现 http://<内部服务>:<端口> 这种写死上游地址（RL-007）。
	host := env("DATAWAY_HOST", "localhost")
	port := env("DATAWAY_PORT", "8090")
	return Config{
		Port:       env("SERVER_PORT", "8085"),
		DatawayURL: "http://" + host + ":" + port,
		Datasource: env("DATAWAY_DATASOURCE", "main"),
		TokenTTL:   time.Duration(ttlHours) * time.Hour,
		PBKDF2Iter: iter,
		// 默认值仅供本地演示；真实部署必须覆盖（见 rcp-ops/k8s/02-secret.example.yaml 的同等做法）。
		BootstrapUsers: map[string]string{
			"admin":    env("IAM_ADMIN_PASSWORD", "Admin@12345"),
			"operator": env("IAM_OPERATOR_PASSWORD", "Operator@12345"),
			"viewer":   env("IAM_VIEWER_PASSWORD", "Viewer@12345"),
		},
	}
}
