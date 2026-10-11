package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 新变量 AGENTPERMIT_ 与旧别名 AAD_ 同时设置时，以新变量为准
func TestNewEnvTakesPrecedenceOverLegacy(t *testing.T) {
	t.Setenv("AGENTPERMIT_BASE_URL", "http://new.example")
	t.Setenv("AAD_BASE_URL", "http://old.example")
	cfg := Load()
	if cfg.BaseURL != "http://new.example" {
		t.Fatalf("应以 AGENTPERMIT_ 变量为准，得到 %s", cfg.BaseURL)
	}
}

// 仅设置旧别名 AAD_ 时仍可读取（兼容更名前的部署）
func TestLegacyEnvStillWorks(t *testing.T) {
	t.Setenv("AAD_BASE_URL", "http://old.example")
	cfg := Load()
	if cfg.BaseURL != "http://old.example" {
		t.Fatalf("旧变量 AAD_BASE_URL 应作为兼容别名生效，得到 %s", cfg.BaseURL)
	}
	t.Setenv("AAD_SECURE_COOKIES", "true")
	if !Load().SecureCookies {
		t.Fatalf("AAD_SECURE_COOKIES 应生效")
	}
	t.Setenv("AAD_SESSION_TTL", "2h")
	if Load().SessionTTL != 2*time.Hour {
		t.Fatalf("AAD_SESSION_TTL 应生效")
	}
}

// 未设置任何变量时使用默认值（新命名）
func TestDefaults(t *testing.T) {
	cfg := Load()
	if cfg.ListenAddr != "127.0.0.1:8080" || cfg.DBPath != DefaultDBPath {
		t.Fatalf("默认值不符合预期: %+v", cfg)
	}
	if DefaultDBPath != "./data/agentpermit.db" {
		t.Fatalf("默认库路径应为新命名")
	}
}

// 存在旧库且无新库时自动沿用旧库，避免创建空数据库
func TestResolveDBPathLegacyFallback(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	os.MkdirAll("data", 0o755)
	os.WriteFile(filepath.Join("data", "aad.db"), []byte("x"), 0o600)

	got, fallback := ResolveDBPath(DefaultDBPath)
	if got != legacyDBPath || !fallback {
		t.Fatalf("应回退旧库，得到 %s fallback=%v", got, fallback)
	}
	// 显式指定旧路径不视为回退
	if got, fb := ResolveDBPath(legacyDBPath); got != legacyDBPath || fb {
		t.Fatalf("显式旧路径应直接使用")
	}
	// 显式自定义路径原样使用
	if got, _ := ResolveDBPath("/tmp/my.db"); got != "/tmp/my.db" {
		t.Fatalf("自定义路径应原样使用")
	}

	// 两个库都存在时使用新库
	os.WriteFile(filepath.Join("data", "agentpermit.db"), []byte("x"), 0o600)
	if got, fb := ResolveDBPath(DefaultDBPath); got != DefaultDBPath || fb {
		t.Fatalf("新旧库并存应用新库，得到 %s fallback=%v", got, fb)
	}

	// 只有新库时用新库
	os.Remove(filepath.Join("data", "aad.db"))
	if got, fb := ResolveDBPath(DefaultDBPath); got != DefaultDBPath || fb {
		t.Fatalf("仅新库应用新库")
	}
}
