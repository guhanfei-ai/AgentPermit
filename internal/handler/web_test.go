package handler

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// 1. 注册、登录、退出
func TestWebRegisterLoginLogout(t *testing.T) {
	e := newTestEnv(t)
	c := newHTTPClient(t, e.ts.URL)

	c.registerViaWeb("alice", "爱丽丝", testPassword)
	c.loginViaWeb("alice", testPassword)

	// 已登录可访问控制台
	resp := c.get("/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("控制台应 200，得到 %d", resp.StatusCode)
	}

	// 退出
	resp, _ = c.postForm("/logout", url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("退出应 302，得到 %d", resp.StatusCode)
	}
	// 退出后控制台跳转登录
	resp = c.get("/")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("退出后应跳转登录，得到 %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// 登录失败统一提示，不区分用户不存在与密码错误
func TestWebLoginFailureUnified(t *testing.T) {
	e := newTestEnv(t)
	e.seedUser("bob", "鲍勃")

	for _, pw := range []string{"wrongpass1", testPassword + "x"} {
		c2 := newHTTPClient(t, e.ts.URL)
		c2.refreshCSRF("/login")
		resp, _ := c2.postForm("/login", url.Values{"username": {"bob"}, "password": {pw}})
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("错误密码登录应重定向回登录页，得到 %d", resp.StatusCode)
		}
	}
	// 不存在的用户同样表现
	c3 := newHTTPClient(t, e.ts.URL)
	c3.refreshCSRF("/login")
	resp, _ := c3.postForm("/login", url.Values{"username": {"nobody"}, "password": {"whatever1"}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("不存在用户登录应重定向回登录页，得到 %d", resp.StatusCode)
	}
}

// 2. CSRF 缺失或错误被拒绝
func TestCSRFRequired(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("carol", "卡罗尔")
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb("carol", testPassword)

	// 缺失 CSRF
	resp, _ := c.do(http.MethodPost, "/agents", url.Values{"name": {"x"}}, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("缺失 CSRF 应 403，得到 %d", resp.StatusCode)
	}
	// 错误 CSRF（直接构造请求体，避免被客户端自动纠正）
	resp, _ = c.do(http.MethodPost, "/agents", url.Values{"name": {"x"}, "csrf_token": {"invalid-token-0000000000"}}, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("错误 CSRF 应 403，得到 %d", resp.StatusCode)
	}
	_ = u
}

// 3. 未登录不能管理 Agent 和能力
func TestAnonymousCannotManage(t *testing.T) {
	e := newTestEnv(t)
	c := newHTTPClient(t, e.ts.URL)
	for _, path := range []string{"/agents", "/capabilities", "/catalog", "/audit"} {
		resp := c.get(path)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
			t.Fatalf("未登录 GET %s 应跳转登录，得到 %d", path, resp.StatusCode)
		}
	}
	resp, _ := c.do(http.MethodPost, "/agents", url.Values{"name": {"x"}, "csrf_token": {"whatever"}}, "")
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("未登录 POST /agents 应被登录跳转或 CSRF 拒绝，得到 %d", resp.StatusCode)
	}
}

// 4. 他人不能管理你的 Agent；5. 他人不能修改你的能力及黑白名单
func TestOwnershipEnforced(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("dave", "戴夫")
	other := e.seedUser("erin", "艾琳")
	agent, _ := e.seedAgent(owner, "owner-agent")
	capability, _ := e.seedCapability(owner, "dave-cap")

	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb("erin", testPassword)

	// 他人撤销 owner 的 Agent → 404，且 Agent 仍 active
	resp, _ := c.postForm("/agents/"+agent.ID+"/revoke", url.Values{})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("他人撤销 Agent 应 404，得到 %d", resp.StatusCode)
	}
	got, err := e.st.GetAgentByID(e.ctx, agent.ID)
	if err != nil || got.Status != "active" {
		t.Fatalf("Agent 不应被他人撤销")
	}

	// 他人停用/编辑 owner 的能力 → 404
	resp, _ = c.postForm("/capabilities/"+capability.ID+"/disable", url.Values{})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("他人停用能力应 404，得到 %d", resp.StatusCode)
	}
	resp, _ = c.postForm("/capabilities/"+capability.ID+"/denylist/add", url.Values{"user_id": {other.ID}})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("他人改黑名单应 404，得到 %d", resp.StatusCode)
	}
	// 他人轮换 owner 的 Service Token → 404
	resp, _ = c.postForm("/capabilities/"+capability.ID+"/service-token/rotate", url.Values{})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("他人轮换 Service Token 应 404，得到 %d", resp.StatusCode)
	}
}

// 6. Agent Token 不能访问 Web 管理接口
func TestAgentTokenCannotAccessWeb(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("frank", "弗兰克")
	_, agentToken := e.seedAgent(u, "web-try")
	c := newHTTPClient(t, e.ts.URL)

	// 带 Agent Token 访问管理页面：仍按匿名处理 → 跳转登录
	resp, _ := c.apiGet("/agents", agentToken)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("Agent Token 访问 Web 应跳转登录，得到 %d", resp.StatusCode)
	}
}

// 18. 无权用户不能读取别人的审计
func TestAuditIsolation(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	_ = zhangsan
	capability, svcToken := e.seedCapability(wangwu, "audit-cap")
	_, agentToken := e.seedAgent(wangwu, "owner-agent")
	_ = capability
	// 触发一条授权事件
	code, out := e.authorize(svcToken, agentToken)
	if code != 200 || out["allowed"] != true {
		t.Fatalf("所有者授权应成功: %v", out)
	}

	// 张三（与事件无关的普通用户）登录查看审计
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb("zhangsan", testPassword)
	page := c.getBody("/audit")
	if strings.Contains(page, "authorize_allowed") || strings.Contains(page, "audit-cap") {
		t.Fatalf("无关用户不应看到他人的授权审计事件")
	}

	// 王五（能力所有者）能看到自己能力上的访问事件
	c2 := newHTTPClient(t, e.ts.URL)
	c2.loginViaWeb("wangwu", testPassword)
	page2 := c2.getBody("/audit")
	if !strings.Contains(page2, "authorize_allowed") {
		t.Fatalf("能力所有者应看到自己能力的访问事件")
	}
	// 自己的身份事件（login_success）可见
	if !strings.Contains(page2, "login_success") {
		t.Fatalf("用户应看到自己的登录事件")
	}
}

// 静态资源可访问（内网无 CDN 依赖）
func TestStaticAssetsServed(t *testing.T) {
	e := newTestEnv(t)
	c := newHTTPClient(t, e.ts.URL)
	for _, path := range []string{"/static/style.css", "/static/app.js"} {
		resp := c.get(path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("静态资源 %s 应 200，得到 %d", path, resp.StatusCode)
		}
	}
}
