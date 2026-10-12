package handler

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
)

func onceCredentialToken(t *testing.T, client *httpClient, location string) string {
	t.Helper()
	page := client.getBody(location)
	match := regexp.MustCompile(`<code id="secret-token">([^<]+)</code>`).FindStringSubmatch(page)
	if match == nil {
		t.Fatal("一次性展示页缺少 Token")
	}
	if resp := client.get(location); resp.StatusCode != http.StatusGone {
		t.Fatalf("原文不能重复查看: %d", resp.StatusCode)
	}
	return match[1]
}

func TestCredentialWebLifecycleAndProtocol(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("credential_owner", "凭证所有者")
	client := newHTTPClient(t, e.ts.URL)
	client.loginViaWeb(owner.Username, testPassword)
	client.refreshCSRF("/agents")
	resp, _ := client.postForm("/agents", url.Values{"name": {"值班协作"}, "description": {"交给值班程序"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("创建凭证: %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	id := strings.TrimSuffix(strings.TrimPrefix(location, "/agents/"), "/token")
	oldToken := onceCredentialToken(t, client, location)
	second, secondToken := e.seedCredential(owner, "机器查询")
	page := client.getBody("/agents")
	if !containsAll(page, "我的调用凭证", owner.Username, id, second.ID, "复制 ID", "撤销凭证") {
		t.Fatal("凭证页必须展示账号归属、记录 ID 与凭证操作")
	}
	if strings.Contains(page, oldToken) || strings.Contains(page, "创建 Agent") {
		t.Fatal("凭证列表不能重复展示 Token 或沿用实例创建语义")
	}

	client.refreshCSRF("/agents")
	resp, _ = client.postForm("/agents/"+id+"/rotate", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("轮换凭证: %d", resp.StatusCode)
	}
	newToken := onceCredentialToken(t, client, resp.Header.Get("Location"))
	if code, _ := getJSON(t, e.ts.URL, "/api/v1/agent/me", oldToken); code != http.StatusUnauthorized {
		t.Fatalf("旧 Token 必须失效: %d", code)
	}
	code, me := getJSON(t, e.ts.URL, "/api/v1/agent/me", newToken)
	if code != http.StatusOK || me["agent_id"] != id || me["agent_name"] != "值班协作" || me["owner_user_id"] != owner.ID || len(me) != 5 {
		t.Fatalf("轮换保留记录与旧 API 协议: %d %v", code, me)
	}
	client.refreshCSRF("/agents")
	resp, _ = client.postForm("/agents/"+id+"/revoke", url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("撤销凭证: %d", resp.StatusCode)
	}
	if code, _ := getJSON(t, e.ts.URL, "/api/v1/agent/me", newToken); code != http.StatusUnauthorized {
		t.Fatalf("已撤销凭证必须失效: %d", code)
	}
	if code, _ := getJSON(t, e.ts.URL, "/api/v1/agent/me", secondToken); code != http.StatusOK {
		t.Fatalf("撤销一条不影响同账号其他凭证: %d", code)
	}
}

func TestCredentialAccountPermissionsSurviveReplacement(t *testing.T) {
	e := newTestEnv(t)
	provider := e.seedUser("provider", "提供者")
	caller := e.seedUser("caller", "调用账号")
	blocked, blockedService := e.seedCapability(provider, "blocked-capability")
	_, otherService := e.seedCapability(provider, "other-capability")
	a, _ := e.seedCredential(caller, "凭证 A")
	_, tokenB := e.seedCredential(caller, "凭证 B")
	if err := e.st.AddDeny(e.ctx, blocked.ID, caller.ID); err != nil {
		t.Fatal(err)
	}
	newTokenA, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	if err := e.st.RotateAgentCredentialToken(e.ctx, a.ID, caller.ID, hash, hint); err != nil {
		t.Fatal(err)
	}
	_, tokenC := e.seedCredential(caller, "黑名单生效后新建的凭证")
	for _, token := range []string{newTokenA, tokenB, tokenC} {
		if code, out := e.authorize(blockedService, token); code != http.StatusOK || out["allowed"] != false || out["reason"] != "user_blacklisted" {
			t.Fatalf("轮换或新建凭证不能绕过账号黑名单: %d %v", code, out)
		}
		if code, out := e.authorize(otherService, token); code != http.StatusOK || out["allowed"] != true {
			t.Fatalf("黑名单不影响其他获准资源: %d %v", code, out)
		}
		if code, _ := getJSON(t, e.ts.URL, "/api/v1/agent/me", token); code != http.StatusOK {
			t.Fatalf("黑名单不撤销凭证: %d", code)
		}
		if code, _ := getJSON(t, e.ts.URL, "/api/v1/capabilities/"+blocked.ID, token); code != http.StatusNotFound {
			t.Fatalf("网页/API 能力访问同受账号策略约束: %d", code)
		}
	}
}

func TestProjectBanAccountPickerAndExplicitScope(t *testing.T) {
	e := newTestEnv(t)
	admin := e.seedUser("project_admin", "项目管理员")
	caller := e.seedUser("project_caller", "协作账号")
	stranger := e.seedUser("stranger", "其他账号")
	project := seedProjectViaWeb(t, e, admin, "credential-project")
	thread := seedThreadViaWeb(t, e, admin, project, "凭证协作")
	a, oldTokenA := e.seedCredential(caller, "凭证 A")
	b, tokenB := e.seedCredential(caller, "凭证 B")
	foreign, _ := e.seedCredential(stranger, "其他账号专属凭证")
	client := newHTTPClient(t, e.ts.URL)
	client.loginViaWeb(admin.Username, testPassword)
	path := "/projects/" + project.Slug + "/admin"
	page := client.getBody(path + "?ban_username=" + caller.Username)
	if !containsAll(page, caller.Username, a.ID, b.ID, `name="scope" required`, "整个账号", "指定凭证") {
		t.Fatal("禁言流程需选择账号及明确范围")
	}
	for _, secret := range []string{oldTokenA, a.TokenHash, a.TokenHint, foreign.ID, foreign.Name} {
		if strings.Contains(page, secret) {
			t.Fatal("凭证选择器仅可展示目标账号的 ID、名称与状态")
		}
	}
	otherClient := newHTTPClient(t, e.ts.URL)
	otherClient.loginViaWeb(caller.Username, testPassword)
	if resp := otherClient.get(path + "?ban_username=" + stranger.Username); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("非项目管理员不能查询他人凭证: %d", resp.StatusCode)
	}
	if !strings.Contains(client.getBody(path+"?ban_username=missing_user"), "未找到这个账号") {
		t.Fatal("不存在的账号应有明确提示")
	}
	client.refreshCSRF(path)
	for _, fields := range []url.Values{
		{"username": {caller.Username}, "scope": {""}},
		{"username": {caller.Username}, "scope": {"credential"}},
		{"username": {caller.Username}, "scope": {"user"}, "agent_id": {a.ID}},
		{"username": {caller.Username}, "scope": {"unknown"}},
		{"username": {caller.Username}, "scope": {"credential"}, "agent_id": {foreign.ID}},
	} {
		resp, _ := client.postForm("/projects/"+project.Slug+"/bans/add", fields)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("非法范围或归属必须拒绝: %d", resp.StatusCode)
		}
		bans, err := e.st.ListProjectBans(e.ctx, project.ID)
		if err != nil || len(bans) != 0 {
			t.Fatalf("非法提交不能产生禁言或扩大范围: %v %v", bans, err)
		}
	}
	resp, _ := client.postForm("/projects/"+project.Slug+"/bans/add", url.Values{
		"username": {caller.Username}, "scope": {"credential"}, "agent_id": {a.ID},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("指定凭证禁言: %d", resp.StatusCode)
	}
	newTokenA, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	if err := e.st.RotateAgentCredentialToken(e.ctx, a.ID, caller.ID, hash, hint); err != nil {
		t.Fatal(err)
	}
	appendPath := "/api/v1/threads/" + thread.ID + "/floors"
	if code, _ := postJSON(t, e.ts.URL, appendPath, newTokenA, `{"body":"拒绝"}`); code != http.StatusForbidden {
		t.Fatalf("轮换后仍受单凭证禁言限制: %d", code)
	}
	if code, _ := getJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID, newTokenA); code != http.StatusOK {
		t.Fatalf("单凭证禁言保持可读: %d", code)
	}
	if code, _ := postJSON(t, e.ts.URL, appendPath, tokenB, `{"body":"同账号其他凭证仍可发言"}`); code != http.StatusCreated {
		t.Fatalf("单凭证禁言不影响其他凭证: %d", code)
	}
	resp, _ = client.postForm("/projects/"+project.Slug+"/bans/add", url.Values{
		"username": {caller.Username}, "scope": {"user"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("账号级禁言: %d", resp.StatusCode)
	}
	_, tokenC := e.seedCredential(caller, "禁言后新建")
	for _, token := range []string{newTokenA, tokenB, tokenC} {
		if code, _ := postJSON(t, e.ts.URL, appendPath, token, `{"body":"拒绝"}`); code != http.StatusForbidden {
			t.Fatalf("账号级覆盖全部现有与新建凭证: %d", code)
		}
	}
}

func TestAccountDisableEnablePreservesUnrevokedCredentials(t *testing.T) {
	e := newTestEnv(t)
	admin := e.seedAdmin("platform_admin", "平台管理员")
	caller := e.seedUser("disable_caller", "调用账号")
	a, tokenA := e.seedCredential(caller, "有效凭证")
	b, tokenB := e.seedCredential(caller, "已撤销凭证")
	if err := e.st.RevokeAgentCredential(e.ctx, b.ID, caller.ID); err != nil {
		t.Fatal(err)
	}
	oldSession := newHTTPClient(t, e.ts.URL)
	oldSession.loginViaWeb(caller.Username, testPassword)
	client := newHTTPClient(t, e.ts.URL)
	client.loginViaWeb(admin.Username, testPassword)
	client.refreshCSRF("/admin/users")
	resp, _ := client.postForm("/admin/users/"+caller.ID+"/disable", url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("禁用账号: %d", resp.StatusCode)
	}
	if code, _ := getJSON(t, e.ts.URL, "/api/v1/agent/me", tokenA); code != http.StatusUnauthorized {
		t.Fatalf("账号禁用期间拒绝凭证: %d", code)
	}
	if resp := oldSession.get("/agents"); resp.StatusCode != http.StatusFound {
		t.Fatalf("禁用账号撤销网页会话: %d", resp.StatusCode)
	}
	resp, _ = client.postForm("/admin/users/"+caller.ID+"/enable", url.Values{})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("启用账号: %d", resp.StatusCode)
	}
	if code, _ := getJSON(t, e.ts.URL, "/api/v1/agent/me", tokenA); code != http.StatusOK {
		t.Fatalf("启用后仍有效凭证恢复可用: %d", code)
	}
	if code, _ := getJSON(t, e.ts.URL, "/api/v1/agent/me", tokenB); code != http.StatusUnauthorized {
		t.Fatalf("启用账号不恢复已撤销凭证: %d", code)
	}
	if resp := oldSession.get("/agents"); resp.StatusCode != http.StatusFound {
		t.Fatalf("重新启用不复活旧网页会话: %d", resp.StatusCode)
	}
	stored, err := e.st.GetAgentCredentialByID(e.ctx, a.ID)
	if err != nil || stored.Status != model.StatusActive {
		t.Fatalf("账号暂停不修改凭证生命周期: %v %v", stored, err)
	}
}

func TestCredentialAuditAttributionAndHistoricalEvents(t *testing.T) {
	e := newTestEnv(t)
	provider := e.seedUser("audit_provider", "提供者")
	caller := e.seedUser("audit_caller", "调用账号")
	credential, token := e.seedCredential(caller, "历史凭证名称")
	capability, serviceToken := e.seedCapability(provider, "audit-credential")
	if code, out := e.authorize(serviceToken, token); code != http.StatusOK || out["allowed"] != true {
		t.Fatalf("授权请求: %d %v", code, out)
	}
	// 模拟已有机器事件：无新列，保留旧事件名与关联记录。
	if err := e.st.InsertAudit(e.ctx, &model.AuditLog{
		Event: "agent_created", ActorUserID: caller.ID, CredentialID: credential.ID, Outcome: "success",
	}); err != nil {
		t.Fatal(err)
	}
	client := newHTTPClient(t, e.ts.URL)
	client.loginViaWeb(provider.Username, testPassword)
	page := client.getBody("/audit")
	if !containsAll(page, "服务授权校验", caller.Username, credential.ID, credential.Name, capability.ID, "能力访问", "authorize_allowed") {
		t.Fatal("服务授权审计需展示凭证、账号、资源与来源")
	}
	if strings.Contains(page, token) || strings.Contains(page, credential.TokenHash) || strings.Contains(page, credential.TokenHint) {
		t.Fatal("审计不能展示 Token 原文、摘要或提示")
	}
	client = newHTTPClient(t, e.ts.URL)
	client.loginViaWeb(caller.Username, testPassword)
	page = client.getBody("/audit")
	if !containsAll(page, "agent_created", "单条调用凭证", "网页会话", credential.ID) {
		t.Fatal("历史凭证事件仍可按新语义读取")
	}
	if row := auditPresentation(&model.AuditLog{Event: "unknown_historical_event", ActorUserID: caller.ID, CredentialID: credential.ID}); row.Source != "未标明" {
		t.Fatal("不能把未知历史事件推测为真人或凭证请求")
	}
}
