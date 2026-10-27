package handler

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// 关闭公开注册后，管理员开户、普通用户登录和凭证使用仍构成完整闭环。
func TestManagedOnboardingWithRegistrationClosed(t *testing.T) {
	e := newTestEnv(t)
	e.srv.cfg.AllowRegistration = false
	admin := e.seedAdmin("managed_admin", "管理员")
	anonymous := newHTTPClient(t, e.ts.URL)
	page := anonymous.getBody("/login")
	if strings.Contains(page, `href="/register"`) || !strings.Contains(page, "账号由团队管理员统一开通") {
		t.Fatal("关闭注册时，登录页与公共导航都应隐藏注册链接并说明开户方式")
	}
	if resp := anonymous.get("/register"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatal("直接访问注册页应返回登录页")
	}
	anonymous.refreshCSRF("/login")
	resp, _ := anonymous.postForm("/register", url.Values{
		"username": {"outsider"}, "display_name": {"外部账号"},
		"password": {testPassword}, "password_confirm": {testPassword},
	})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatal("直接提交注册表单也必须被拒绝")
	}
	if _, err := e.st.GetUserByUsername(e.ctx, "outsider"); err != store.ErrNotFound {
		t.Fatal("关闭注册时不能创建账号")
	}

	manager := newHTTPClient(t, e.ts.URL)
	manager.loginViaWeb(admin.Username, testPassword)
	manager.refreshCSRF("/admin/users")
	resp, _ = manager.postForm("/admin/users", url.Values{
		"username": {" employee "}, "display_name": {" 员工甲 "},
		"password": {testPassword}, "password_confirm": {testPassword},
		"role": {model.UserRoleAdmin}, // 伪造角色也不能通过开户入口提升权限。
	})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin/users" {
		t.Fatalf("管理员开户失败: %d", resp.StatusCode)
	}
	employee, err := e.st.GetUserByUsername(e.ctx, "employee")
	if err != nil {
		t.Fatal(err)
	}
	if employee.Role != model.UserRoleUser || !employee.IsActive() || employee.DisplayName != "员工甲" {
		t.Fatalf("新账号必须是有效普通用户: %+v", employee)
	}
	if employee.PasswordHash == testPassword || !auth.CheckPassword(employee.PasswordHash, testPassword) {
		t.Fatal("开户密码必须使用现有 bcrypt 流程存储")
	}
	if page := manager.getBody("/admin/users"); !strings.Contains(page, "员工甲") || strings.Contains(page, testPassword) {
		t.Fatal("用户列表应显示新账号且不能回显密码")
	}
	logs, err := e.st.ListAuditAdmin(e.ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	created := 0
	for _, log := range logs {
		if strings.Contains(log.Detail, testPassword) {
			t.Fatal("审计不能记录密码")
		}
		if log.Event == "user_created" {
			created++
			if log.ActorUserID != admin.ID || log.SubjectUserID != employee.ID || log.Detail != employee.Username || log.RequestID == "" {
				t.Fatalf("开户审计必须关联管理员、普通账号和请求: %+v", log)
			}
			if row := auditPresentation(log); row.Source != "网页会话" || row.Scope != "账号开通" {
				t.Fatal("开户审计必须有明确来源与范围")
			}
		}
	}
	if created != 1 {
		t.Fatalf("应恰好产生一条开户审计，得到 %d", created)
	}

	client := newHTTPClient(t, e.ts.URL)
	client.loginViaWeb(employee.Username, testPassword)
	if resp := client.get("/admin/users"); resp.StatusCode != http.StatusForbidden {
		t.Fatal("开户得到的普通账号不能访问管理员页面")
	}
	client.refreshCSRF("/agents")
	resp, _ = client.postForm("/agents", url.Values{"name": {"团队工具调用"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("新账号应可签发本人凭证: %d", resp.StatusCode)
	}
	token := onceCredentialToken(t, client, resp.Header.Get("Location"))
	if code, me := getJSON(t, e.ts.URL, "/api/v1/agent/me", token); code != http.StatusOK || me["owner_user_id"] != employee.ID {
		t.Fatalf("新凭证应保持既有账号归属协议: %d %v", code, me)
	}
	manager.refreshCSRF("/admin/users")
	resp, _ = manager.postForm("/admin/users/"+employee.ID+"/disable", url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("管理员禁用账号失败: %d", resp.StatusCode)
	}
	if code, _ := getJSON(t, e.ts.URL, "/agent/v1/me", token); code != http.StatusUnauthorized {
		t.Fatal("禁用账号后调用凭证应立即失效")
	}
	if resp := client.get("/agents"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatal("禁用新账号后网页会话必须失效")
	}
}

func TestManagedAccountCreationRequiresAdminAndCSRF(t *testing.T) {
	e := newTestEnv(t)
	e.srv.cfg.AllowRegistration = false
	admin := e.seedAdmin("admin", "管理员")
	user := e.seedUser("employee", "员工")
	_, token := e.seedCredential(admin, "管理员持有的调用凭证")
	fields := func() url.Values {
		return url.Values{
			"username": {"unauthorized"}, "display_name": {"越权账号"},
			"password": {testPassword}, "password_confirm": {testPassword},
		}
	}
	anonymous := newHTTPClient(t, e.ts.URL)
	anonymous.refreshCSRF("/login")
	if resp, _ := anonymous.postForm("/admin/users", fields()); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatal("匿名用户不能开户")
	}
	withCSRF := fields()
	withCSRF.Set("csrf_token", anonymous.csrf)
	if resp, _ := anonymous.do(http.MethodPost, "/admin/users", withCSRF, token); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatal("即使属于管理员的 Agent Token，也不能作为管理员网页会话开户")
	}
	client := newHTTPClient(t, e.ts.URL)
	client.loginViaWeb(user.Username, testPassword)
	if resp, _ := client.postForm("/admin/users", fields()); resp.StatusCode != http.StatusForbidden {
		t.Fatal("普通用户不能开户")
	}
	manager := newHTTPClient(t, e.ts.URL)
	manager.loginViaWeb(admin.Username, testPassword)
	for _, csrf := range []string{"", "invalid-csrf"} {
		values := fields()
		values.Set("csrf_token", csrf)
		if resp, _ := manager.do(http.MethodPost, "/admin/users", values, ""); resp.StatusCode != http.StatusForbidden {
			t.Fatal("管理员开户必须有有效 CSRF Token")
		}
	}
	if _, err := e.st.GetUserByUsername(e.ctx, "unauthorized"); err != store.ErrNotFound {
		t.Fatal("拒绝请求不能创建账号")
	}
}

func TestManagedAccountCreationValidatesAndPreservesExistingUsers(t *testing.T) {
	e := newTestEnv(t)
	e.srv.cfg.AllowRegistration = false
	admin := e.seedAdmin("admin", "管理员")
	existing := e.seedUser("existing", "原有账号")
	manager := newHTTPClient(t, e.ts.URL)
	manager.loginViaWeb(admin.Username, testPassword)
	manager.refreshCSRF("/admin/users")
	for _, tc := range []struct {
		name, username, displayName, password, confirm, message string
	}{
		{"非法用户名", "bad.user", "员工", testPassword, testPassword, "用户名仅允许"},
		{"空显示名", "invalid", "  ", testPassword, testPassword, "显示名不能为空"},
		{"超长中文显示名", "invalid", strings.Repeat("名", 65), testPassword, testPassword, "显示名不能为空"},
		{"短密码", "invalid", "员工", "q7z", "q7z", "8-72 字节"},
		{"bcrypt上限", "invalid", "员工", strings.Repeat("密", 25), strings.Repeat("密", 25), "8-72 字节"},
		{"确认不一致", "invalid", "员工", testPassword, "different", "两次输入"},
		{"重复账号", existing.Username, "覆盖原有账号", "AnotherPassword", "AnotherPassword", "未修改已有账号"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := manager.postForm("/admin/users", url.Values{
				"username": {tc.username}, "display_name": {tc.displayName},
				"password": {tc.password}, "password_confirm": {tc.confirm},
			})
			if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin/users" {
				t.Fatalf("无效开户应返回管理页: %d", resp.StatusCode)
			}
			if page := manager.getBody("/admin/users"); !strings.Contains(page, tc.message) || strings.Contains(page, tc.password) {
				t.Fatal("无效开户应显示可理解的错误且不回显密码")
			}
		})
	}
	users, err := e.st.ListUsers(e.ctx)
	if err != nil || len(users) != 2 {
		t.Fatalf("失败请求不能创建账号: count=%d err=%v", len(users), err)
	}
	unchanged, err := e.st.GetUserByID(e.ctx, existing.ID)
	if err != nil || unchanged.DisplayName != existing.DisplayName || unchanged.PasswordHash != existing.PasswordHash || unchanged.Role != existing.Role {
		t.Fatal("重复开户不能覆盖原有账号的名称、密码或权限")
	}
	// 中文显示名按字符计数，合法的 64 字显示名与 bcrypt 上限密码可正常开户。
	password := strings.Repeat("P", 72)
	resp, _ := manager.postForm("/admin/users", url.Values{
		"username": {"boundary"}, "display_name": {strings.Repeat("名", 64)},
		"password": {password}, "password_confirm": {password},
	})
	boundary, err := e.st.GetUserByUsername(e.ctx, "boundary")
	if resp.StatusCode != http.StatusFound || err != nil || !auth.CheckPassword(boundary.PasswordHash, password) {
		t.Fatal("合法的中文名称和边界长度密码应可开户")
	}
}

func TestManagedBrandingUsesEscapedSharedLayout(t *testing.T) {
	e := newTestEnv(t)
	e.srv.cfg.AllowRegistration = false
	client := newHTTPClient(t, e.ts.URL)
	if page := client.getBody("/login"); !strings.Contains(page, "登录 · AgentPermit</title>") || !strings.Contains(page, `<a href="/">AgentPermit</a>`) {
		t.Fatal("团队版本默认应使用 AgentPermit 展示名称")
	}
	e.srv.cfg.SiteName = `<script>alert("brand")</script>`
	e.srv.cfg.OrganizationName = `<img src=x onerror=alert("company")>`
	_, errorPage := client.do(http.MethodPost, "/login", url.Values{"csrf_token": {"invalid"}}, "")
	for _, page := range []string{client.getBody("/login"), errorPage} {
		if strings.Contains(page, e.srv.cfg.SiteName) || strings.Contains(page, e.srv.cfg.OrganizationName) ||
			!strings.Contains(page, html.EscapeString(e.srv.cfg.SiteName)) || !strings.Contains(page, html.EscapeString(e.srv.cfg.OrganizationName)) {
			t.Fatal("品牌和团队名称必须在登录页和错误页共享布局中转义")
		}
	}
	e.seedUser("employee", "员工")
	client.loginViaWeb("employee", testPassword)
	if page := client.getBody("/agents"); !strings.Contains(page, html.EscapeString(e.srv.cfg.OrganizationName)) {
		t.Fatal("品牌配置应覆盖登录后的页面")
	}
}
