// agentpermit-demo-machine-service 是独立的演示业务服务进程，
// 证明业务服务不在平台内部：它通过 HTTP 回调平台完成每次调用的授权校验。
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"agentpermit/internal/demoservice"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	// AGENTPERMIT_ 为规范前缀；更名前的 AAD_ / DEMO_ 变量仍作为兼容别名
	baseURL := envOr("AGENTPERMIT_BASE_URL", "AAD_BASE_URL", "http://127.0.0.1:8080")
	serviceToken := envFirst("AGENTPERMIT_SERVICE_TOKEN", "AAD_SERVICE_TOKEN")
	listenAddr := envOr("AGENTPERMIT_DEMO_LISTEN_ADDR", "DEMO_LISTEN_ADDR", "127.0.0.1:9090")

	if serviceToken == "" {
		fmt.Fprintln(os.Stderr, "缺少 AGENTPERMIT_SERVICE_TOKEN 环境变量（兼容旧名 AAD_SERVICE_TOKEN）。请在平台网页获取该能力的 Service Token 并配置。")
		os.Exit(1)
	}

	svc := demoservice.New(baseURL, serviceToken, logger)
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	logger.Info("agentpermit-demo-machine-service 启动", "listen", listenAddr, "platform", baseURL)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("服务退出", "err", err)
		os.Exit(1)
	}
}

// envOr 依次检查变量名，取第一个非空值；全空返回默认值。
func envOr(names ...string) string {
	def := names[len(names)-1]
	if v := envFirst(names[:len(names)-1]...); v != "" {
		return v
	}
	return def
}

func envFirst(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}
