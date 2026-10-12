package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/config"
	"agentpermit/internal/database"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// testEnv 每个测试独立：临时 SQLite 数据库 + httptest 平台实例。
type testEnv struct {
	t   *testing.T
	srv *Server
	ts  *httptest.Server
	st  *store.Store
	ctx context.Context
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	st := store.New(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.Config{
		ListenAddr:        "127.0.0.1:0",
		DBPath:            filepath.Join(dir, "test.db"),
		BaseURL:           "http://platform.test",
		AllowRegistration: true,
		SecureCookies:     false,
		SessionTTL:        time.Hour,
	}
	srv, err := New(cfg, st, logger)
	if err != nil {
		t.Fatalf("构建 Server 失败: %v", err)
	}
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return &testEnv{t: t, srv: srv, ts: ts, st: st, ctx: context.Background()}
}

// httpClient 带 Cookie Jar 的浏览器式客户端。
type httpClient struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

func newHTTPClient(t *testing.T, base string) *httpClient {
	jar, _ := cookiejar.New(nil)
	return &httpClient{t: t, base: base, http: &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		// 不自动跟随重定向，便于断言 302 与 Location
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}
}

var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// refreshCSRF GET 一个页面，提取当前应使用的 CSRF Token。
func (c *httpClient) refreshCSRF(path string) {
	c.t.Helper()
	body := c.getBody(path)
	m := csrfPattern.FindStringSubmatch(body)
	if m == nil {
		c.t.Fatalf("页面 %s 未找到 csrf_token", path)
	}
	c.csrf = m[1]
}

func (c *httpClient) do(method, path string, vals url.Values, bearer string) (*http.Response, string) {
	c.t.Helper()
	var body io.Reader
	if vals != nil {
		body = strings.NewReader(vals.Encode())
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		c.t.Fatalf("构造请求失败: %v", err)
	}
	if vals != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("请求 %s %s 失败: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (c *httpClient) get(path string) *http.Response {
	resp, _ := c.do(http.MethodGet, path, nil, "")
	return resp
}

func (c *httpClient) getBody(path string) string {
	_, text := c.do(http.MethodGet, path, nil, "")
	return text
}

// postForm 提交表单（自动携带当前 CSRF Token）。
func (c *httpClient) postForm(path string, vals url.Values) (*http.Response, string) {
	c.t.Helper()
	if c.csrf == "" {
		c.t.Fatalf("postForm 前需要 refreshCSRF")
	}
	vals.Set("csrf_token", c.csrf)
	return c.do(http.MethodPost, path, vals, "")
}

// apiGet / apiPost JSON API 调用。
func (c *httpClient) apiGet(path, bearer string) (*http.Response, string) {
	return c.do(http.MethodGet, path, nil, bearer)
}

// registerViaWeb 通过网页完成注册。
func (c *httpClient) registerViaWeb(username, displayName, password string) {
	c.t.Helper()
	c.refreshCSRF("/register")
	resp, _ := c.postForm("/register", url.Values{
		"username":         {username},
		"display_name":     {displayName},
		"password":         {password},
		"password_confirm": {password},
	})
	if resp.StatusCode != http.StatusFound {
		c.t.Fatalf("注册 %s 失败: status=%d", username, resp.StatusCode)
	}
}

// loginViaWeb 通过网页登录。
func (c *httpClient) loginViaWeb(username, password string) {
	c.t.Helper()
	c.refreshCSRF("/login")
	resp, _ := c.postForm("/login", url.Values{"username": {username}, "password": {password}})
	if resp.StatusCode != http.StatusFound {
		c.t.Fatalf("登录 %s 失败: status=%d", username, resp.StatusCode)
	}
	c.refreshCSRF("/")
}

// ---- 数据库直连 seed 辅助 ----

const testPassword = "password123"

func (e *testEnv) seedUser(username, displayName string) *model.User {
	return e.seedUserWithRole(username, displayName, model.UserRoleUser)
}

func (e *testEnv) seedAdmin(username, displayName string) *model.User {
	return e.seedUserWithRole(username, displayName, model.UserRoleAdmin)
}

func (e *testEnv) seedUserWithRole(username, displayName, role string) *model.User {
	e.t.Helper()
	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		e.t.Fatalf("哈希密码失败: %v", err)
	}
	u := &model.User{
		ID: store.NewID(), Username: username, DisplayName: displayName,
		PasswordHash: hash, Role: role, Status: model.StatusActive,
	}
	if err := e.st.CreateUser(e.ctx, u); err != nil {
		e.t.Fatalf("创建用户 %s 失败: %v", username, err)
	}
	return u
}

// seedCredential 为账号创建调用凭证，返回 (credential, 原始 Token)。
func (e *testEnv) seedCredential(u *model.User, name string) (*model.AgentCredential, string) {
	e.t.Helper()
	token, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	a := &model.AgentCredential{
		ID: store.NewID(), OwnerUserID: u.ID, Name: name, Status: model.StatusActive,
		TokenHash: hash, TokenHint: hint,
	}
	if err := e.st.CreateAgentCredential(e.ctx, a); err != nil {
		e.t.Fatalf("创建调用凭证失败: %v", err)
	}
	return a, token
}

// seedCapability 为用户创建能力（含 Service Token），返回 (capability, 原始 Service Token)。
// mustSeedCredential 用显式 Token（如旧前缀）创建凭证记录，供兼容性测试使用。
func mustSeedCredential(e *testEnv, ownerUserID, name, tokenHash, hint string) *model.AgentCredential {
	e.t.Helper()
	a := &model.AgentCredential{
		ID: store.NewID(), OwnerUserID: ownerUserID, Name: name, Status: model.StatusActive,
		TokenHash: tokenHash, TokenHint: hint,
	}
	if err := e.st.CreateAgentCredential(e.ctx, a); err != nil {
		e.t.Fatalf("创建调用凭证失败: %v", err)
	}
	return a
}

// mustSeedCapability 用显式 Service 凭证创建能力，供兼容性测试使用。
func mustSeedCapability(e *testEnv, ownerUserID, slug, credHash, credHint string) *model.Capability {
	e.t.Helper()
	c := &model.Capability{
		ID: store.NewID(), OwnerUserID: ownerUserID, Name: "查询机器配置-" + slug, Slug: slug,
		EndpointURL: "http://127.0.0.1:9090", HTTPMethod: "GET",
		APIPath: "/machines/{machine_id}/spec", AccessMode: model.AccessModeTeam, Status: model.StatusActive,
	}
	cred := &model.ServiceCredential{CapabilityID: c.ID, TokenHash: credHash, TokenHint: credHint}
	if err := e.st.CreateCapability(e.ctx, c, cred); err != nil {
		e.t.Fatalf("创建能力失败: %v", err)
	}
	return c
}

func (e *testEnv) seedCapability(u *model.User, slug string) (*model.Capability, string) {
	e.t.Helper()
	token, hash, hint := auth.NewToken(auth.ServiceTokenPrefix)
	c := &model.Capability{
		ID: store.NewID(), OwnerUserID: u.ID, Name: "查询机器配置-" + slug, Slug: slug,
		Description: "测试能力", EndpointURL: "http://127.0.0.1:9090", HTTPMethod: "GET",
		APIPath: "/machines/{machine_id}/spec", AccessMode: model.AccessModeTeam, Status: model.StatusActive,
	}
	cred := &model.ServiceCredential{CapabilityID: c.ID, TokenHash: hash, TokenHint: hint}
	if err := e.st.CreateCapability(e.ctx, c, cred); err != nil {
		e.t.Fatalf("创建能力失败: %v", err)
	}
	return c, token
}

// authorize 调用平台授权接口（模拟独立服务行为）。
func (e *testEnv) authorize(serviceToken, agentToken string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/service/authorize",
		strings.NewReader(`{"agent_token":"`+agentToken+`"}`))
	req.Header.Set("Authorization", "Bearer "+serviceToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("授权请求失败: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		e.t.Fatalf("解析授权响应失败: %v, body=%s", err, string(b))
	}
	return resp.StatusCode, out
}
