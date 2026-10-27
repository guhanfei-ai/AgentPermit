// Package config 从环境变量加载平台与演示服务的配置。
//
// 变量命名规范：统一使用 AGENTPERMIT_ 前缀。
// 更名前的 AAD_ 前缀变量仍作为兼容别名读取；
// 新旧变量同时设置时，以 AGENTPERMIT_ 变量为准。
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config 是平台服务器配置。全部字段均可通过环境变量覆盖。
type Config struct {
	ListenAddr        string         // AGENTPERMIT_LISTEN_ADDR，默认 127.0.0.1:8080
	DBPath            string         // AGENTPERMIT_DB_PATH，默认 ./data/agentpermit.db
	BaseURL           string         // AGENTPERMIT_BASE_URL，页面展示用，默认 http://127.0.0.1:8080
	AllowRegistration bool           // AGENTPERMIT_ALLOW_REGISTRATION，默认 true（仅限本地演示）
	SecureCookies     bool           // AGENTPERMIT_SECURE_COOKIES，默认 false（本地 HTTP 演示）
	SessionTTL        time.Duration  // AGENTPERMIT_SESSION_TTL，默认 24h
	LogLevel          string         // AGENTPERMIT_LOG_LEVEL，默认 info
	SiteName          string         // AGENTPERMIT_SITE_NAME，页面品牌
	OrganizationName  string         // AGENTPERMIT_ORGANIZATION_NAME，可选展示名称
	Environment       string         // AGENTPERMIT_ENV，空值保留旧客户端变量名
	ServerAgentsPath  string         // AGENTPERMIT_AGENT_GUIDE_PATH，可选外置接入说明
	UsageGuideURL     string         // AGENTPERMIT_USAGE_GUIDE_URL，可选使用规范入口
	TrustedProxies    []netip.Prefix // AGENTPERMIT_TRUSTED_PROXIES，默认不信任转发头
}

const DefaultSiteName = "AgentPermit"

// DefaultDBPath 新部署的默认数据库路径。
const DefaultDBPath = "./data/agentpermit.db"

// legacyDBPath 更名前的默认数据库路径；存在旧库且无新库时自动沿用。
const legacyDBPath = "./data/aad.db"

// ResolveDBPath 返回实际使用的数据库路径：
// 显式配置（任一别名）优先；未显式配置时，若旧库存在且新库不存在则沿用旧库，
// 避免更名后创建空数据库。第二返回值说明是否发生了旧路径回退（仅用于日志提示）。
func ResolveDBPath(configured string) (string, bool) {
	if configured == legacyDBPath {
		return legacyDBPath, false
	}
	if configured != DefaultDBPath || envStr("DB_PATH", "") != "" {
		return configured, false // 用户显式指定的其他路径
	}
	if fileExists(legacyDBPath) && !fileExists(DefaultDBPath) {
		return legacyDBPath, true
	}
	return DefaultDBPath, false
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Load 从环境变量读取配置，未设置时使用本地演示友好的默认值。
// 注意：Go 程序本身不会自动读取 .env 文件，需要由 Makefile / shell 先 source。
func Load() Config {
	return Config{
		ListenAddr:        envStr("LISTEN_ADDR", "127.0.0.1:8080"),
		DBPath:            envStr("DB_PATH", DefaultDBPath),
		BaseURL:           envStr("BASE_URL", "http://127.0.0.1:8080"),
		AllowRegistration: envBool("ALLOW_REGISTRATION", true),
		SecureCookies:     envBool("SECURE_COOKIES", false),
		SessionTTL:        envDuration("SESSION_TTL", 24*time.Hour),
		LogLevel:          envStr("LOG_LEVEL", "info"),
		SiteName:          envStr("SITE_NAME", DefaultSiteName),
		OrganizationName:  envStr("ORGANIZATION_NAME", ""),
		Environment:       normalizeEnvironment(envStr("ENV", "")),
		ServerAgentsPath:  strings.TrimSpace(envStr("AGENT_GUIDE_PATH", "")),
		UsageGuideURL:     strings.TrimSpace(envStr("USAGE_GUIDE_URL", "")),
		TrustedProxies:    trustedProxies(),
	}
}

func trustedProxies() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, raw := range strings.FieldsFunc(envStr("TRUSTED_PROXIES", ""), func(r rune) bool { return r == ',' || r == ' ' }) {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			panic(fmt.Sprintf("AGENTPERMIT_TRUSTED_PROXIES 包含无效 CIDR %q", raw))
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

// envStr 读取配置：AGENTPERMIT_ 前缀优先，AAD_ 前缀为兼容别名。
func envStr(name, def string) string {
	if v := os.Getenv("AGENTPERMIT_" + name); v != "" {
		return v
	}
	if v := os.Getenv("AAD_" + name); v != "" {
		return v
	}
	return def
}

func envBool(name string, def bool) bool {
	v := firstEnv("AGENTPERMIT_"+name, "AAD_"+name)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		panic(fmt.Sprintf("配置 %s=%q 不是合法布尔值", name, v))
	}
	return b
}

func envDuration(name string, def time.Duration) time.Duration {
	v := firstEnv("AGENTPERMIT_"+name, "AAD_"+name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		panic(fmt.Sprintf("配置 %s=%q 不是合法的正时长", name, v))
	}
	return d
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}
