package handler

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// createContentCapability 经真实网页表单创建纯内容能力，覆盖浏览器默认 GET 的清洗。
func createContentCapability(t *testing.T, e *testEnv, c *httpClient, owner *model.User) *model.Capability {
	t.Helper()
	c.refreshCSRF("/capabilities/new")
	resp, _ := c.postForm("/capabilities", contentCapabilityForm("Published v1", "SPEC and RUNBOOK v1"))
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("创建纯内容能力应 303: %d", resp.StatusCode)
	}
	caps, err := e.st.ListCapabilitiesByOwner(e.ctx, owner.ID)
	if err != nil || len(caps) != 1 {
		t.Fatalf("应创建一个能力: %v, len=%d", err, len(caps))
	}
	capability := caps[0]
	if resp.Header.Get("Location") != "/capabilities/"+capability.ID+"/versions" {
		t.Fatalf("纯内容创建后应进入版本管理: %s", resp.Header.Get("Location"))
	}
	if capability.EndpointURL != "" || capability.HTTPMethod != "" || capability.APIPath != "" {
		t.Fatalf("纯内容不应保留虚构 HTTP 字段: %+v", capability)
	}
	if _, err := e.st.GetServiceCredentialByCapability(e.ctx, capability.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("纯内容不应创建服务凭证: %v", err)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieOnce {
			t.Fatal("纯内容创建不应携带一次性服务凭证")
		}
	}
	return capability
}

func contentCapabilityForm(name, content string) url.Values {
	return url.Values{
		"name": {name}, "slug": {"content-runbook"}, "description": {name + " summary"},
		"spec_markdown": {content}, "http_method": {"GET"}, "access_mode": {model.AccessModeTeam},
	}
}

func assertContentSnapshot(t *testing.T, e *testEnv, capabilityID, token, name, content string, version int) {
	t.Helper()
	code, body := getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capabilityID, token)
	if code != http.StatusOK || body["version"] != float64(version) || body["name"] != name || body["spec_markdown"] != content {
		t.Fatalf("纯内容发布快照不匹配: %d %v", code, body)
	}
	if body["has_http_binding"] != false || body["authentication"] != nil || body["endpoint_url"] != "" || body["http_method"] != "" || body["api_path"] != "" {
		t.Fatalf("纯内容不能声明 HTTP 调用: %v", body)
	}
}

func TestContentCapabilityLifecycle(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("author", "作者")
	reader := e.seedUser("reader", "读者")
	_, token1 := e.seedCredential(reader, "reader-1")
	_, token2 := e.seedCredential(reader, "reader-2")
	author := newHTTPClient(t, e.ts.URL)
	author.loginViaWeb(owner.Username, testPassword)
	viewer := newHTTPClient(t, e.ts.URL)
	viewer.loginViaWeb(reader.Username, testPassword)
	capability := createContentCapability(t, e, author, owner)
	path := "/capabilities/" + capability.ID

	assertContentSnapshot(t, e, capability.ID, token1, "Published v1", "SPEC and RUNBOOK v1", 1)
	for _, pagePath := range []string{"/catalog", "/catalog/" + capability.ID, path + "/access", path + "/versions"} {
		resp, page := author.do(http.MethodGet, pagePath, nil, "")
		if resp.StatusCode != http.StatusOK || !strings.Contains(page, "纯内容") {
			t.Fatalf("纯内容页面应完整渲染: %s, %d", pagePath, resp.StatusCode)
		}
		if pagePath == "/catalog/"+capability.ID && strings.Contains(page, "curl -H") {
			t.Fatal("纯内容详情不应生成空地址 curl 示例")
		}
	}
	resp, _ := author.postForm(path+"/service-token/rotate", url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("纯内容不能生成 Service Token: %d", resp.StatusCode)
	}
	if _, err := e.st.GetServiceCredentialByCapability(e.ctx, capability.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("直接请求也不能生成纯内容凭证: %v", err)
	}

	// 草稿名称、描述和正文在目录列表、页面标题及 Agent API 中都不可见。
	resp, _ = author.postForm(path, contentCapabilityForm("DRAFT_ONLY_v2", "DRAFT_ONLY_body"))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("保存纯内容草稿失败: %d", resp.StatusCode)
	}
	assertContentSnapshot(t, e, capability.ID, token1, "Published v1", "SPEC and RUNBOOK v1", 1)
	for _, pagePath := range []string{"/catalog", "/catalog/" + capability.ID} {
		page := viewer.getBody(pagePath)
		if strings.Contains(page, "DRAFT_ONLY") || !strings.Contains(page, "Published v1") {
			t.Fatalf("草稿泄露到目录: %s", pagePath)
		}
	}
	code, body := getJSON(t, e.ts.URL, "/api/v1/capabilities", token1)
	if code != http.StatusOK || len(body["capabilities"].([]any)) != 1 || body["capabilities"].([]any)[0].(map[string]any)["name"] != "Published v1" {
		t.Fatalf("能力列表应读取发布快照: %d %v", code, body)
	}

	resp, _ = author.postForm(path+"/publish", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("发布纯内容草稿失败: %d", resp.StatusCode)
	}
	assertContentSnapshot(t, e, capability.ID, token1, "DRAFT_ONLY_v2", "DRAFT_ONLY_body", 2)
	resp, _ = author.postForm(path+"/latest", url.Values{"version": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("latest 回滚失败: %d", resp.StatusCode)
	}
	assertContentSnapshot(t, e, capability.ID, token1, "Published v1", "SPEC and RUNBOOK v1", 1)

	// 所有权检查同样覆盖纯内容的发布、回滚和服务凭证入口。
	for _, suffix := range []string{"/publish", "/latest", "/service-token/rotate"} {
		resp, _ = viewer.postForm(path+suffix, url.Values{"version": {"2"}})
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("读者不得管理他人的纯内容能力: %s %d", suffix, resp.StatusCode)
		}
	}

	// 先放入白名单，再拉黑；内容回滚不能恢复账号名下任一个 Agent 的访问权。
	author.postForm(path+"/access/mode", url.Values{"access_mode": {model.AccessModeAllowlist}})
	author.postForm(path+"/allowlist/add", url.Values{"user_id": {reader.ID}})
	assertContentSnapshot(t, e, capability.ID, token2, "Published v1", "SPEC and RUNBOOK v1", 1)
	author.postForm(path+"/denylist/add", url.Values{"user_id": {reader.ID}})
	author.postForm(path+"/latest", url.Values{"version": {"2"}})
	for _, token := range []string{token1, token2} {
		code, _ = getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capability.ID, token)
		if code != http.StatusNotFound {
			t.Fatalf("纯内容黑名单应覆盖全部 Agent: %d", code)
		}
		code, body = getJSON(t, e.ts.URL, "/api/v1/capabilities", token)
		if code != http.StatusOK || len(body["capabilities"].([]any)) != 0 {
			t.Fatalf("黑名单账号不应发现纯内容能力: %d %v", code, body)
		}
	}
	if resp := viewer.get("/catalog/" + capability.ID); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("网页读取同样应被拒绝: %d", resp.StatusCode)
	}
}

func TestContentCapabilityHTTPBindingVersions(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("author", "作者")
	reader := e.seedUser("reader", "读者")
	_, agentToken := e.seedCredential(reader, "reader")
	author := newHTTPClient(t, e.ts.URL)
	author.loginViaWeb(owner.Username, testPassword)
	capability := createContentCapability(t, e, author, owner)
	path := "/capabilities/" + capability.ID
	form := contentCapabilityForm("HTTP v2", "HTTP RUNBOOK v2")
	form.Set("endpoint_url", "http://127.0.0.1:9090")
	form.Set("api_path", "/machines/{machine_id}/spec")
	author.postForm(path, form)
	assertContentSnapshot(t, e, capability.ID, agentToken, "Published v1", "SPEC and RUNBOOK v1", 1)
	resp, _ := author.postForm(path+"/service-token/rotate", url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("仅草稿添加 HTTP 绑定不能生成凭证: %d", resp.StatusCode)
	}

	author.postForm(path+"/publish", url.Values{})
	code, body := getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capability.ID, agentToken)
	if code != http.StatusOK || body["has_http_binding"] != true || body["endpoint_url"] != form.Get("endpoint_url") || body["authentication"].(map[string]any)["credential"] != "caller_agent_token" {
		t.Fatalf("发布后应包含完整 HTTP 声明: %d %v", code, body)
	}
	if page := author.getBody(path + "/access"); !strings.Contains(page, "生成 Service Token") {
		t.Fatal("首次绑定应提供生成凭证入口")
	}
	resp, _ = author.postForm(path+"/service-token/rotate", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("首次生成服务凭证失败: %d", resp.StatusCode)
	}
	page := author.getBody(resp.Header.Get("Location"))
	match := regexp.MustCompile(`<code id="secret-token">([^<]+)</code>`).FindStringSubmatch(page)
	if match == nil {
		t.Fatal("应一次性展示新凭证")
	}
	serviceToken := match[1]
	code, decision := e.authorize(serviceToken, agentToken)
	if code != http.StatusOK || decision["allowed"] != true {
		t.Fatalf("新生成的凭证必须实际可用: %d %v", code, decision)
	}
	if resp := author.get(path + "/service-token"); resp.StatusCode != http.StatusGone {
		t.Fatalf("凭证原文只能读取一次: %d", resp.StatusCode)
	}

	// 删除草稿绑定不影响正在使用的已发布 HTTP 版本。
	author.postForm(path, contentCapabilityForm("Content v3", "RUNBOOK v3"))
	code, decision = e.authorize(serviceToken, agentToken)
	if code != http.StatusOK || decision["allowed"] != true {
		t.Fatalf("未发布的移除绑定不应影响服务: %d %v", code, decision)
	}
	author.postForm(path+"/publish", url.Values{})
	assertContentSnapshot(t, e, capability.ID, agentToken, "Content v3", "RUNBOOK v3", 3)
	code, decision = e.authorize(serviceToken, agentToken)
	if code != http.StatusOK || decision["allowed"] != false || decision["reason"] != "no_http_binding" {
		t.Fatalf("纯内容发布后不能继续授权 HTTP 服务: %d %v", code, decision)
	}
	author.postForm(path+"/latest", url.Values{"version": {"2"}})
	code, decision = e.authorize(serviceToken, agentToken)
	if code != http.StatusOK || decision["allowed"] != true {
		t.Fatalf("latest 回指 HTTP 版本后原凭证仍兼容: %d %v", code, decision)
	}
	author.postForm(path+"/denylist/add", url.Values{"user_id": {reader.ID}})
	author.postForm(path+"/latest", url.Values{"version": {"3"}})
	code, decision = e.authorize(serviceToken, agentToken)
	if code != http.StatusOK || decision["reason"] != "user_blacklisted" {
		t.Fatalf("HTTP 绑定变化不应覆盖访问拒绝原因: %d %v", code, decision)
	}
}

func TestHTTPBoundCapabilityCreation(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("author", "作者")
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb(owner.Username, testPassword)
	form := contentCapabilityForm("HTTP capability", "RUNBOOK")
	form.Set("endpoint_url", "http://127.0.0.1:9090")
	form.Set("api_path", "/machines/{machine_id}/spec")
	resp, _ := c.postForm("/capabilities", form)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasSuffix(resp.Header.Get("Location"), "/service-token") {
		t.Fatalf("原 HTTP 创建流程应保留: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	page := c.getBody(resp.Header.Get("Location"))
	if !strings.Contains(page, `id="secret-token">ap_service_`) {
		t.Fatal("原 HTTP 创建流程应继续签发服务凭证")
	}
}

func TestCapabilityMissingPublishedSnapshotDoesNotLeakDraft(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("author", "作者")
	capability, _ := e.seedCapability(owner, "missing-snapshot")
	_, token := e.seedCredential(owner, "author-agent")
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb(owner.Username, testPassword)
	if _, err := e.st.DB().ExecContext(e.ctx, `UPDATE capabilities SET name=?, spec_markdown=?, latest_version=999 WHERE id=?`, "PRIVATE_DRAFT", "PRIVATE_DRAFT", capability.ID); err != nil {
		t.Fatal(err)
	}
	code, _ := getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capability.ID, token)
	if code != http.StatusNotFound {
		t.Fatalf("缺失发布快照时不能回退草稿: %d", code)
	}
	code, body := getJSON(t, e.ts.URL, "/api/v1/capabilities", token)
	if code != http.StatusOK || len(body["capabilities"].([]any)) != 0 {
		t.Fatalf("能力列表不能回退草稿: %d %v", code, body)
	}
	resp, page := c.do(http.MethodGet, "/catalog/"+capability.ID, nil, "")
	if resp.StatusCode != http.StatusNotFound || strings.Contains(page, "PRIVATE_DRAFT") || strings.Contains(c.getBody("/catalog"), "PRIVATE_DRAFT") {
		t.Fatal("网页目录不能回退草稿")
	}
}

func TestCapabilityOptionalHTTPValidation(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, method, path string
		valid                        bool
	}{
		{"content", "", "", "", true},
		{"http", "https://service.example", "GET", "/status", true},
		{"missing_path", "https://service.example", "GET", "", false},
		{"missing_endpoint", "", "GET", "/status", false},
		{"missing_method", "https://service.example", "", "/status", false},
		{"invalid_scheme", "ftp://service.example", "GET", "/status", false},
		{"invalid_method", "https://service.example", "TRACE", "/status", false},
		{"invalid_path", "https://service.example", "GET", "status", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := validateCapabilityInput("能力", "valid-slug", "描述", tc.endpoint, tc.method, tc.path, "RUNBOOK", false)
			if (msg == "") != tc.valid {
				t.Fatalf("HTTP 绑定完整性校验不符: %q", msg)
			}
		})
	}
}
