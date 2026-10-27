package handler

import (
	"net/http"
	"strings"
	"testing"

	"agentpermit/internal/model"
)

func TestAuditViewsSeparateAdminAndPersonal(t *testing.T) {
	e := newTestEnv(t)
	admin := e.seedAdmin("audit_admin", "审计管理员")
	user := e.seedUser("audit_user", "审计用户")
	adminCredential, _ := e.seedCredential(admin, "管理员自己的凭证")
	userCredential, _ := e.seedCredential(user, "普通用户的凭证")
	for _, entry := range []*model.AuditLog{
		{Event: "agent_created", ActorUserID: admin.ID, CredentialID: adminCredential.ID, Outcome: "success"},
		{Event: "agent_created", ActorUserID: user.ID, CredentialID: userCredential.ID, Outcome: "success"},
	} {
		if err := e.st.InsertAudit(e.ctx, entry); err != nil {
			t.Fatal(err)
		}
	}

	manager := newHTTPClient(t, e.ts.URL)
	manager.loginViaWeb(admin.Username, testPassword)
	for _, tc := range []struct {
		name, path, title string
		want, hidden      []string
	}{
		{
			name: "管理员查看个人审计", path: "/audit", title: "审计我的Agent",
			want: []string{adminCredential.ID}, hidden: []string{userCredential.ID},
		},
		{
			name: "管理员查看全局审计", path: "/admin/audit", title: "全局审计",
			want: []string{adminCredential.ID, userCredential.ID},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, page := manager.do(http.MethodGet, tc.path, nil, "")
			if resp.StatusCode != http.StatusOK || !strings.Contains(page, "<h1>"+tc.title+"</h1>") {
				t.Fatalf("审计页面应显示对应范围的标题: status=%d", resp.StatusCode)
			}
			for _, value := range tc.want {
				if !strings.Contains(page, value) {
					t.Fatalf("审计页面缺少应可见的凭证记录 %s", value)
				}
			}
			for _, value := range tc.hidden {
				if strings.Contains(page, value) {
					t.Fatalf("个人审计不应包含无关账号的凭证记录 %s", value)
				}
			}
			if !containsAll(page, `href="/admin/audit"`, ">全局审计</a>", `href="/audit"`, ">审计我的Agent</a>") {
				t.Fatal("管理员菜单与我的菜单应同时提供各自的审计入口")
			}
		})
	}

	client := newHTTPClient(t, e.ts.URL)
	client.loginViaWeb(user.Username, testPassword)
	page := client.getBody("/audit")
	if !containsAll(page, "<h1>审计我的Agent</h1>", userCredential.ID) || strings.Contains(page, adminCredential.ID) || strings.Contains(page, `href="/admin/audit"`) {
		t.Fatal("普通用户只能看到个人审计入口和本人的审计记录")
	}
	if resp := client.get("/admin/audit"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("普通用户不能直接访问全局审计: status=%d", resp.StatusCode)
	}
	anonymous := newHTTPClient(t, e.ts.URL)
	if resp := anonymous.get("/admin/audit"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("未登录访问全局审计应跳转登录: status=%d", resp.StatusCode)
	}
}
