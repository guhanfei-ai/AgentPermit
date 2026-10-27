package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

func TestLoginStorageErrorDoesNotDereferenceMissingUser(t *testing.T) {
	e := newTestEnv(t)
	if err := e.st.DB().Close(); err != nil {
		t.Fatal(err)
	}
	_, failure := e.srv.loginWithPassword(httptest.NewRecorder(), httptest.NewRequest("POST", "/login", nil), "nobody", "not-a-real-password")
	if failure == nil || failure.status != http.StatusInternalServerError {
		t.Fatal("存储错误应明确返回内部错误，不能 panic 或伪装成密码错误")
	}
}

func TestPasswordChangeRollsBackIfSessionRevocationFails(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("atomic_password", "事务验证")
	if err := e.st.CreateSession(e.ctx, "session-fixture", u.ID, "csrf-fixture", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DB().Exec(`CREATE TRIGGER reject_revocation BEFORE UPDATE OF revoked_at ON sessions BEGIN SELECT RAISE(FAIL, 'test revocation failure'); END`); err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("replacement-test-pass")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.ChangeUserPassword(e.ctx, u.ID, u.PasswordHash, hash); err == nil {
		t.Fatal("会话撤销失败不能提交密码变更")
	}
	got, err := e.st.GetUserByID(e.ctx, u.ID)
	if err != nil || got.PasswordHash != u.PasswordHash {
		t.Fatal("事务未回滚密码变更")
	}
}

func TestRevokedCredentialPageAndRegistrationBounds(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("revoked_view", "撤销显示")
	a, _ := e.seedCredential(u, "撤销测试")
	if err := e.st.RevokeAgentCredential(e.ctx, a.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb(u.Username, testPassword)
	resp, body := c.do("GET", "/agents", nil, "")
	if resp.StatusCode != 200 || !strings.Contains(body, "已撤销") || !strings.Contains(body, "</html>") {
		t.Fatal("撤销凭证页面没有完整渲染")
	}
	if msg := validateNewUser("unicode_user", strings.Repeat("名", 64), testPassword, testPassword); msg != "" {
		t.Fatal("显示名应按字符数校验", msg)
	}
	if msg := validateNewUser("unicode_user", "名字", strings.Repeat("x", 73), strings.Repeat("x", 73)); msg == "" {
		t.Fatal("超过 bcrypt 字节上限的密码应在入口拒绝")
	}
}

func TestLegacyAuthorizationHonorsCentralControls(t *testing.T) {
	e := newTrustEnv(t)
	capability, serviceToken := e.seedCapability(e.admin, "legacy-trust")
	if _, err := e.st.PublishCapability(e.ctx, capability.ID); err != nil {
		t.Fatal(err)
	}
	if status, body := e.authorize(serviceToken, e.agentToken); status != 200 || body["allowed"] != true {
		t.Fatalf("旧能力访问基线失败: %d %v", status, body)
	}
	for _, kind := range []string{"person", "credential", "condition"} {
		user, credential := "", ""
		if kind == "person" {
			user = e.person.ID
		}
		if kind == "credential" {
			credential = e.credential.ID
		}
		ban := e.ban(kind, user, credential, "", "")
		status, body := e.authorize(serviceToken, e.agentToken)
		if status != 200 || body["allowed"] != false || body["retryable"] != false || body["ai_instruction"] == nil || body["user"] != nil {
			t.Fatalf("旧入口应保持拒绝协议且不泄露身份: %d %v", status, body)
		}
		if err := e.st.ReleaseWorkBan(e.ctx, ban.ID, e.admin.ID); err != nil {
			t.Fatal(err)
		}
	}
	p := &model.HolidayPlan{ID: store.NewID(), CreatedBy: e.admin.ID, Reason: "测试暂停", TriggerAt: e.st.Now(), EndsAt: e.st.Now().Add(time.Minute)}
	if err := e.st.CreateHoliday(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(11)
	if status, body := e.authorize(serviceToken, e.agentToken); status != 200 || body["allowed"] != false || body["reason"] != "holiday_lockdown" {
		t.Fatalf("旧入口绕过全局暂停: %d %v", status, body)
	}
}

func TestUnlockPasswordRequiresExplicitSetup(t *testing.T) {
	e := newTestEnv(t)
	admin := e.seedAdmin("setup_admin", "设置管理员")
	hash, err := e.st.GetHolidayUnlockPasswordHash(e.ctx)
	if err != nil || hash != "" {
		t.Fatal("不能有默认解锁密码")
	}
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb(admin.Username, testPassword)
	c.refreshCSRF("/admin/settings")
	form := url.Values{"current_password": {testPassword}, "password": {"custom-unlock-pass"}, "password_confirm": {"custom-unlock-pass"}}
	resp, _ := c.postForm("/admin/settings/holiday-unlock-password", form)
	if resp.StatusCode != 303 {
		t.Fatalf("初始配置失败: %d", resp.StatusCode)
	}
	hash, err = e.st.GetHolidayUnlockPasswordHash(e.ctx)
	if err != nil || !auth.CheckPassword(hash, "custom-unlock-pass") {
		t.Fatal("配置没有持久化")
	}
	form.Set("password", "other-unlock-pass")
	form.Set("password_confirm", "other-unlock-pass")
	resp, _ = c.postForm("/admin/settings/holiday-unlock-password", form)
	if resp.StatusCode != 403 {
		t.Fatal("已设置后不能再用管理员密码替代当前解锁密码")
	}
	form.Set("current_password", "custom-unlock-pass")
	resp, _ = c.postForm("/admin/settings/holiday-unlock-password", form)
	if resp.StatusCode != 303 {
		t.Fatal("应支持验证旧密码后轮换解锁密码")
	}
}

func TestAgentGuideEmbeddedOverrideAndSafeRendering(t *testing.T) {
	e := newTestEnv(t)
	request := func(accept string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/agent", nil)
		r.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		e.srv.Routes().ServeHTTP(w, r)
		return w
	}
	w := request("text/plain")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "# AgentPermit") || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "<nav") {
		t.Fatal("默认说明必须随二进制可用且不混入会话")
	}
	e.srv.cfg.Environment = "TEST"
	w = request("text/plain")
	if !strings.Contains(w.Body.String(), "AGENTPERMIT_TEST_AGENT_TOKEN") {
		t.Fatal("环境变量说明未适配")
	}
	file := filepath.Join(t.TempDir(), "guide.md")
	e.srv.cfg.ServerAgentsPath = file
	if err := os.WriteFile(file, []byte("# Safe guide\n\n<script>alert('unsafe')</script>\n\n[bad](javascript:alert(1))"), 0600); err != nil {
		t.Fatal(err)
	}
	w = request("text/html")
	if w.Code != 200 || strings.Contains(w.Body.String(), "<script>alert") || strings.Contains(w.Body.String(), `href="javascript:`) || !strings.Contains(w.Body.String(), "Safe guide") {
		t.Fatal("文档渲染不安全或失败")
	}
	if err := os.WriteFile(file, []byte("# Updated guide"), 0600); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(request("text/plain").Body.String(), "Updated guide") {
		t.Fatal("外置说明更新未生效")
	}
	e.srv.cfg.ServerAgentsPath = filepath.Join(t.TempDir(), "missing.md")
	if request("text/plain").Code != 503 {
		t.Fatal("显式配置缺失文件时不能假装成功")
	}
}

func TestPublicURLOnlyTrustsConfiguredProxy(t *testing.T) {
	e := newTestEnv(t)
	r := httptest.NewRequest("GET", "http://local.example.test/agents", nil)
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("X-Forwarded-Host", "public.example.test")
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := e.srv.publicAPIBaseURL(r, ""); got != "http://local.example.test" {
		t.Fatal("不可信转发头改变了公开地址", got)
	}
	e.srv.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	if got := e.srv.publicAPIBaseURL(r, ""); got != "https://public.example.test" {
		t.Fatal("可信代理地址解析失败", got)
	}
	r.Header.Set("X-Forwarded-Host", "invalid.example.test/path")
	if got := e.srv.publicAPIBaseURL(r, ""); got != "https://local.example.test" {
		t.Fatal("非法 Host 不应进入配置示例", got)
	}
}

func TestTrustIssuanceRechecksRequestedOrigin(t *testing.T) {
	e := newTrustEnv(t)
	requestedOrigin := e.server.Origin
	e.server.Origin = "https://updated.example.test"
	if err := e.st.SaveTrustedServer(e.ctx, e.server, false); err != nil {
		t.Fatal(err)
	}
	_, hash, hint := auth.NewToken(temporaryTokenPrefix)
	g := &model.TemporaryGrant{ID: store.NewID(), UserID: e.person.ID, CredentialID: e.credential.ID, ServerID: e.server.ID, TargetOrigin: requestedOrigin, IssuedBy: e.person.ID, TokenHash: hash, TokenHint: hint, ParentTokenHash: e.credential.TokenHash}
	if err := e.st.IssueTemporaryGrant(e.ctx, g); err != store.ErrInvalidTrust {
		t.Fatalf("服务地址变更后仍为旧目标签发：%v", err)
	}
	if _, err := e.st.GetTemporaryGrant(e.ctx, g.ID); err != store.ErrNotFound {
		t.Fatalf("拒绝签发后不应留下凭证：%v", err)
	}
	g.TargetOrigin = e.server.Origin
	if err := e.st.IssueTemporaryGrant(e.ctx, g); err != nil {
		t.Fatalf("匹配当前目标时应允许签发：%v", err)
	}
}

func TestPasswordChangeRejectsStaleHash(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("stale_password", "并发保护")
	if err := e.st.ChangeUserPassword(context.Background(), u.ID, "stale-hash", "new-hash"); err != store.ErrConflict {
		t.Fatal("旧摘要应被拒绝", err)
	}
}
