// agentpermit（AgentPermit 平台）主程序：提供网页管理界面、Agent API 与服务授权校验 API。
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/config"
	"agentpermit/internal/database"
	"agentpermit/internal/handler"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

func main() {
	var (
		createAdmin      = flag.Bool("create-admin", false, "创建管理员后退出（不启动服务）")
		adminUsername    = flag.String("admin-username", "", "管理员用户名")
		adminPassword    = flag.String("admin-password", "", "管理员密码（至少 8 位，仅从命令行参数或交互传入，不设默认值）")
		adminDisplayName = flag.String("admin-display-name", "管理员", "管理员显示名")
	)
	flag.Parse()

	cfg := config.Load()
	// 未显式配置数据库路径时，若存在更名前的旧库（./data/aad.db）则沿用，避免创建空库
	dbPath, legacyFallback := config.ResolveDBPath(cfg.DBPath)
	cfg.DBPath = dbPath
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	if legacyFallback {
		logger.Info("检测到更名前的数据库，自动沿用",
			"db", dbPath, "hint", "设置 AGENTPERMIT_DB_PATH 可显式指定新路径")
	}

	db, err := database.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "数据库初始化失败:", err)
		os.Exit(1)
	}
	st := store.New(db)

	if *createAdmin {
		runCreateAdmin(cfg, st, logger, *adminUsername, *adminPassword, *adminDisplayName)
		return
	}

	srv, err := handler.New(cfg, st, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "初始化服务失败:", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		logger.Info("平台启动", "listen", cfg.ListenAddr, "db", cfg.DBPath,
			"allow_registration", cfg.AllowRegistration, "secure_cookies", cfg.SecureCookies)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("服务退出", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	logger.Info("正在关闭…")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	db.Close()
}

// runCreateAdmin 显式创建首个管理员：要求用户名与密码来自命令行参数，不提供隐藏默认密码。
func runCreateAdmin(cfg config.Config, st *store.Store, logger *slog.Logger, username, password, displayName string) {
	if username == "" || password == "" {
		fmt.Fprintln(os.Stderr, "用法: agentpermit -create-admin -admin-username <用户名> -admin-password <密码> [-admin-display-name <显示名>]")
		os.Exit(2)
	}
	if len(password) < 8 {
		fmt.Fprintln(os.Stderr, "管理员密码至少 8 位。")
		os.Exit(2)
	}
	ctx, contextCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer contextCancel()

	if _, err := st.GetUserByUsername(ctx, username); err == nil {
		fmt.Fprintf(os.Stderr, "用户 %s 已存在，未做任何修改。\n", username)
		os.Exit(1)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "密码哈希失败:", err)
		os.Exit(1)
	}
	u := &model.User{
		ID:           store.NewID(),
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: hash,
		Role:         model.UserRoleAdmin,
		Status:       model.StatusActive,
	}
	if err := st.CreateUser(ctx, u); err != nil {
		fmt.Fprintln(os.Stderr, "创建管理员失败:", err)
		os.Exit(1)
	}
	logger.Info("管理员创建成功", "username", username, "db", cfg.DBPath)
	fmt.Printf("管理员 %s 创建成功。\n", username)
}
