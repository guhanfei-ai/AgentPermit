package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
)

func readJSONResponse(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("响应不是 JSON: status=%d body=%s err=%v", resp.StatusCode, raw, err)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("JSON 响应头不正确: %v", resp.Header)
	}
	if resp.Header.Get("X-Request-ID") == "" || resp.Header.Get("Location") != "" {
		t.Fatal("JSON 接口必须携带请求 ID，且不能重定向")
	}
	return body
}

func (c *httpClient) webJSON(method, path, body string) (*http.Response, map[string]any) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp, readJSONResponse(c.t, resp)
}

func (c *httpClient) refreshWebCSRF() {
	c.t.Helper()
	resp, body := c.webJSON(http.MethodGet, "/web/v1/csrf", "")
	value, ok := body["csrf_token"].(string)
	if resp.StatusCode != http.StatusOK || !ok || value == "" {
		c.t.Fatalf("获取 Web API CSRF 失败: status=%d body=%v", resp.StatusCode, body)
	}
	c.csrf = value
}

func (c *httpClient) loginViaWebAPI(username, password string) {
	c.t.Helper()
	c.refreshWebCSRF()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, out := c.webJSON(http.MethodPost, "/web/v1/auth/login", string(body))
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("JSON 登录失败: status=%d body=%v", resp.StatusCode, out)
	}
	c.refreshWebCSRF()
}

func expectJSONError(t *testing.T, resp *http.Response, body map[string]any, status int, code string) {
	t.Helper()
	detail, ok := body["error"].(map[string]any)
	if resp.StatusCode != status || !ok || detail["code"] != code || body["request_id"] != resp.Header.Get("X-Request-ID") {
		t.Fatalf("错误响应应为 %d/%s，实际 status=%d body=%v", status, code, resp.StatusCode, body)
	}
}

func TestAgentRouteMigrationAndPolicy(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("route_owner", "所有者")
	caller := e.seedUser("route_caller", "调用者")
	_, token := e.seedCredential(caller, "迁移测试凭证")
	project := seedProjectViaWeb(t, e, owner, "route-channel")
	thread := seedThreadViaWeb(t, e, owner, project, "接口迁移验证")

	for _, pair := range [][2]string{
		{"/api/v1/agent/me", "/agent/v1/me"},
		{"/api/v1/projects", "/agent/v1/projects"},
		{"/api/v1/projects/" + project.Slug, "/agent/v1/projects/" + project.Slug},
		{"/api/v1/projects/" + project.ID + "/threads", "/agent/v1/projects/" + project.ID + "/threads"},
		{"/api/v1/threads/" + thread.ID + "?after=0&limit=1", "/agent/v1/threads/" + thread.ID + "?after=0&limit=1"},
	} {
		t.Run(pair[1], func(t *testing.T) {
			oldStatus, oldBody := getJSON(t, e.ts.URL, pair[0], token)
			newStatus, newBody := getJSON(t, e.ts.URL, pair[1], token)
			if oldStatus != http.StatusOK || newStatus != http.StatusOK || !reflect.DeepEqual(oldBody, newBody) {
				t.Fatalf("新旧接口不等价: old=%d/%v new=%d/%v", oldStatus, oldBody, newStatus, newBody)
			}
		})
	}
	for _, prefix := range []string{"/agent/v1", "/api/v1"} {
		status, body := postJSON(t, e.ts.URL, prefix+"/threads/"+thread.ID+"/floors", token, `{"body":"接口迁移后的协作记录"}`)
		if status != http.StatusCreated || body["floor"] == nil {
			t.Fatalf("追加楼层失败: %d %v", status, body)
		}
	}
	for _, prefix := range []string{"/agent/v1", "/api/v1"} {
		status, _ := postJSON(t, e.ts.URL, prefix+"/projects", token, `{"name":"不应创建"}`)
		if status != http.StatusMethodNotAllowed {
			t.Fatalf("Agent 不能通过 %s 创建频道: %d", prefix, status)
		}
	}

}

func TestAPINamespaceCredentialIsolation(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("isolated_user", "隔离验证")
	_, agentToken := e.seedCredential(u, "调用凭证")
	anonymous := newHTTPClient(t, e.ts.URL)
	for _, token := range []string{"", agentToken, "invalid-token"} {
		resp, raw := anonymous.apiGet("/web/v1/me", token)
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(raw, `"code":"unauthorized"`) || resp.Header.Get("Location") != "" {
			t.Fatalf("Bearer 不能替代网页会话: %d %s", resp.StatusCode, raw)
		}
	}
	for _, token := range []string{"", "invalid-token"} {
		status, _ := getJSON(t, e.ts.URL, "/agent/v1/me", token)
		if status != http.StatusUnauthorized {
			t.Fatalf("缺失或无效凭证 不能访问 Agent 入口: %d", status)
		}
	}
	browser := newHTTPClient(t, e.ts.URL)
	browser.loginViaWebAPI(u.Username, testPassword)
	for _, path := range []string{"/agent/v1/me", "/api/v1/agent/me"} {
		resp, body := browser.webJSON(http.MethodGet, path, "")
		expectJSONError(t, resp, body, http.StatusUnauthorized, "unauthorized")
	}

}

func TestWebAPISessionLifecycle(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("json_user", "JSON 用户")
	c := newHTTPClient(t, e.ts.URL)
	resp, body := c.webJSON(http.MethodGet, "/web/v1/me", "")
	expectJSONError(t, resp, body, http.StatusUnauthorized, "unauthorized")
	c.refreshWebCSRF()
	anonymousCSRF := c.csrf
	loginBody := `{"username":"json_user","password":"password123"}`
	c.csrf = ""
	resp, body = c.webJSON(http.MethodPost, "/web/v1/auth/login", loginBody)
	expectJSONError(t, resp, body, http.StatusForbidden, "csrf_invalid")
	c.csrf = anonymousCSRF
	resp, body = c.webJSON(http.MethodPost, "/web/v1/auth/login", loginBody)
	if resp.StatusCode != http.StatusOK || body["user"].(map[string]any)["id"] != u.ID {
		t.Fatalf("JSON 登录失败: %d %v", resp.StatusCode, body)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieSession && (!cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/") {
			t.Fatal("会话 Cookie 属性发生变化")
		}
	}
	base, _ := url.Parse(e.ts.URL)
	var sessionToken string
	for _, cookie := range c.http.Jar.Cookies(base) {
		if cookie.Name == cookieSession {
			sessionToken = cookie.Value
		}
	}
	if !strings.HasPrefix(sessionToken, auth.SessionTokenPrefix) {
		t.Fatal("JSON 登录没有签发原有格式的会话")
	}
	session, err := e.st.GetSessionByTokenHash(e.ctx, auth.HashToken(sessionToken))
	if err != nil || session.UserID != u.ID || session.TokenHash == sessionToken {
		t.Fatalf("会话持久化不正确: %v", err)
	}
	c.refreshWebCSRF()
	if c.csrf == anonymousCSRF || c.csrf != session.CSRFToken {
		t.Fatal("登录后必须切换到新会话的 CSRF Token")
	}
	resp, body = c.webJSON(http.MethodGet, "/web/v1/me", "")
	user := body["user"].(map[string]any)
	if resp.StatusCode != http.StatusOK || len(user) != 5 || user["id"] != u.ID || user["role"] != model.UserRoleUser {
		t.Fatalf("真人信息包含未约定字段或缺失字段: %v", body)
	}
	if resp := c.get("/"); resp.StatusCode != http.StatusOK {
		t.Fatal("JSON 登录会话不能用于原有网页")
	}
	sessionCSRF := c.csrf
	c.csrf = anonymousCSRF
	resp, body = c.webJSON(http.MethodPost, "/web/v1/auth/logout", "")
	expectJSONError(t, resp, body, http.StatusForbidden, "csrf_invalid")
	c.csrf = sessionCSRF
	resp, body = c.webJSON(http.MethodPost, "/web/v1/auth/logout", "")
	if resp.StatusCode != http.StatusOK || body["ok"] != true {
		t.Fatalf("退出失败: %d %v", resp.StatusCode, body)
	}
	session, err = e.st.GetSessionByTokenHash(e.ctx, auth.HashToken(sessionToken))
	if err != nil || session.RevokedAt == nil {
		t.Fatal("退出必须撤销服务端会话")
	}
	replay := newHTTPClient(t, e.ts.URL)
	replay.http.Jar.SetCookies(base, []*http.Cookie{{Name: cookieSession, Value: sessionToken}})
	resp, body = replay.webJSON(http.MethodGet, "/web/v1/me", "")
	expectJSONError(t, resp, body, http.StatusUnauthorized, "unauthorized")
}

func TestWebAPILoginFailureAndValidation(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("json_failure", "登录失败验证")
	c := newHTTPClient(t, e.ts.URL)
	c.refreshWebCSRF()
	var first map[string]any
	for _, username := range []string{u.Username, "missing_user"} {
		payload, _ := json.Marshal(map[string]string{"username": username, "password": "wrong_password"})
		resp, body := c.webJSON(http.MethodPost, "/web/v1/auth/login", string(payload))
		expectJSONError(t, resp, body, http.StatusUnauthorized, "invalid_credentials")
		if first != nil && !reflect.DeepEqual(first, body["error"]) {
			t.Fatal("不存在账号与错误密码不应返回不同错误")
		}
		first = body["error"].(map[string]any)
	}
	for _, payload := range []string{"{", "[]", "null", "{}", `{"username":"json_failure","password":"password123","role":"admin"}`, `{"username":"json_failure","password":"password123"} {}`} {
		resp, body := c.webJSON(http.MethodPost, "/web/v1/auth/login", payload)
		expectJSONError(t, resp, body, http.StatusBadRequest, "invalid_request")
	}
	payload := `{"username":"json_failure","password":"` + strings.Repeat("x", maxBodyBytes) + `"}`
	resp, body := c.webJSON(http.MethodPost, "/web/v1/auth/login", payload)
	expectJSONError(t, resp, body, http.StatusRequestEntityTooLarge, "body_too_large")
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/web/v1/auth/login", strings.NewReader("username=json_failure"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	expectJSONError(t, resp, readJSONResponse(t, resp), http.StatusUnsupportedMediaType, "unsupported_media_type")
	if err := e.st.SetUserStatus(e.ctx, u.ID, model.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	resp, body = c.webJSON(http.MethodPost, "/web/v1/auth/login", `{"username":"json_failure","password":"password123"}`)
	expectJSONError(t, resp, body, http.StatusForbidden, "user_disabled")
}

func TestWebAPILoginSharesHTMLRateLimit(t *testing.T) {
	e := newTestEnv(t)
	e.seedUser("shared_limit", "共享限流")
	e.srv.limiter.limit = 2
	c := newHTTPClient(t, e.ts.URL)
	c.refreshWebCSRF()
	resp, body := c.webJSON(http.MethodPost, "/web/v1/auth/login", `{"username":"shared_limit","password":"wrong_password"}`)
	expectJSONError(t, resp, body, http.StatusUnauthorized, "invalid_credentials")
	resp, _ = c.postForm("/login", url.Values{"username": {"shared_limit"}, "password": {"wrong_password"}})
	if resp.StatusCode != http.StatusFound {
		t.Fatal("HTML 登录失败语义发生变化")
	}
	resp, body = c.webJSON(http.MethodPost, "/web/v1/auth/login", `{"username":"shared_limit","password":"password123"}`)
	expectJSONError(t, resp, body, http.StatusTooManyRequests, "rate_limited")
	resp, _ = c.postForm("/login", url.Values{"username": {"shared_limit"}, "password": {testPassword}})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatal("切换 HTML 入口不能绕过 JSON 登录限流")
	}
}

func TestWebAPILegacySessionAndInvalidation(t *testing.T) {
	for _, state := range []string{"legacy", "expired", "revoked", "disabled"} {
		t.Run(state, func(t *testing.T) {
			e := newTestEnv(t)
			u := e.seedUser("legacy_json", "存量会话")
			token := "aad_session_" + auth.NewRandomHex(32)
			csrf := auth.NewRandomHex(16)
			expires := time.Now().Add(time.Hour)
			if state == "expired" {
				expires = time.Now().Add(-time.Hour)
			}
			if err := e.st.CreateSession(e.ctx, auth.HashToken(token), u.ID, csrf, expires); err != nil {
				t.Fatal(err)
			}
			if state == "revoked" {
				if err := e.st.RevokeSession(e.ctx, auth.HashToken(token)); err != nil {
					t.Fatal(err)
				}
			}
			if state == "disabled" {
				if err := e.st.SetUserStatus(e.ctx, u.ID, model.StatusDisabled); err != nil {
					t.Fatal(err)
				}
			}
			c := newHTTPClient(t, e.ts.URL)
			base, _ := url.Parse(e.ts.URL)
			c.http.Jar.SetCookies(base, []*http.Cookie{{Name: legacyCookieSession, Value: token}})
			resp, body := c.webJSON(http.MethodGet, "/web/v1/me", "")
			if state != "legacy" {
				expectJSONError(t, resp, body, http.StatusUnauthorized, "unauthorized")
				return
			}
			if resp.StatusCode != http.StatusOK || body["user"].(map[string]any)["id"] != u.ID {
				t.Fatal("旧会话不能用于新 Web API")
			}
			c.refreshWebCSRF()
			if c.csrf != csrf {
				t.Fatal("旧会话 CSRF 不兼容")
			}
			resp, _ = c.webJSON(http.MethodPost, "/web/v1/auth/logout", "")
			cleared := map[string]bool{}
			for _, cookie := range resp.Cookies() {
				if cookie.MaxAge < 0 {
					cleared[cookie.Name] = true
				}
			}
			if !cleared[cookieSession] || !cleared[legacyCookieSession] {
				t.Fatal("退出必须同时清理新旧会话 Cookie")
			}
		})
	}
}

func TestAPINamespaceRoutingErrorsAndMetrics(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("api_metrics", "接口计数")
	_, token := e.seedCredential(u, "接口计数凭证")
	c := newHTTPClient(t, e.ts.URL)
	for _, prefix := range []string{"/web/v1", "/agent/v1", "/api/v1"} {
		resp, body := c.webJSON(http.MethodGet, prefix+"/not-found", "")
		expectJSONError(t, resp, body, http.StatusNotFound, "not_found")
	}
	resp, body := c.webJSON(http.MethodPost, "/agent/v1/me", "{}")
	expectJSONError(t, resp, body, http.StatusMethodNotAllowed, "method_not_allowed")
	if resp.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("方法错误缺少 Allow: %v", resp.Header)
	}
	c.loginViaWebAPI(u.Username, testPassword)
	before := e.srv.metrics.snapshot(u.ID, false).Requests
	c.webJSON(http.MethodGet, "/web/v1/csrf", "")
	c.webJSON(http.MethodGet, "/web/v1/me", "")
	getJSON(t, e.ts.URL, "/agent/v1/me", token)
	getJSON(t, e.ts.URL, "/api/v1/agent/me", token)
	if after := e.srv.metrics.snapshot(u.ID, false).Requests; after != before+4 {
		t.Fatalf("新入口未计入当前账号 API 请求: before=%d after=%d", before, after)
	}
	for _, prefix := range []string{"/web/v1", "/agent/v1"} {
		rec := httptest.NewRecorder()
		h := e.srv.baseMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("test") }))
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, prefix+"/panic", nil))
		if rec.Code != http.StatusInternalServerError || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || e.srv.metrics.snapshot("", true).Current != 0 {
			t.Fatal("新 API 入口的 panic 恢复或请求释放不正确")
		}
	}
}
