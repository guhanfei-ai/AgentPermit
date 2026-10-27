package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/database"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

type trustEnv struct {
	*testEnv
	admin, person           *model.User
	credential              *model.AgentCredential
	agentToken, serverToken string
	server                  *model.TrustedServer
	clock                   atomic.Int64
}

const testUnlockPassword = "local-test-unlock-pass"

func newTrustEnv(t *testing.T) *trustEnv {
	e := &trustEnv{testEnv: newTestEnv(t)}
	e.admin = e.seedAdmin("trust_admin", "授信管理员")
	e.person = e.seedUser("trust_reader", "被授信人")
	e.credential, e.agentToken = e.seedCredential(e.person, "测试Agent")
	e.clock.Store(time.Now().UTC().Truncate(time.Second).Unix())
	e.st = store.NewWithClock(e.st.DB(), func() time.Time { return time.Unix(e.clock.Load(), 0).UTC() })
	e.srv.store = e.st
	e.server, e.serverToken = e.makeServer("主服务", "http://127.0.0.1:9876")
	hash, err := auth.HashPassword(testUnlockPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.UpdateHolidayUnlockPasswordHash(e.ctx, hash); err != nil {
		t.Fatal(err)
	}
	return e
}
func (e *trustEnv) makeServer(name, origin string) (*model.TrustedServer, string) {
	e.t.Helper()
	token, hash, hint := auth.NewToken(serviceTokenPrefix)
	v := &model.TrustedServer{ID: store.NewID(), Name: name, Kind: "Server", Description: "用途", Environment: "生产", Origin: origin, OwnerUserID: e.admin.ID, Status: "active", TokenHash: hash, TokenHint: hint}
	if err := e.st.SaveTrustedServer(e.ctx, v, true); err != nil {
		e.t.Fatal(err)
	}
	return v, token
}

// makeGroup 在Server下登记变量编组；一个Server可挂多个编组，不新增服务登记。
func (e *trustEnv) makeGroup(server *model.TrustedServer, name, definition string) *model.FieldGroup {
	e.t.Helper()
	f := &model.FieldGroup{ID: store.NewID(), ServerID: server.ID, Name: name, Description: "测试编组", Definition: definition, CreatedBy: e.admin.ID}
	if err := e.st.SaveFieldGroup(e.ctx, f); err != nil {
		e.t.Fatal(err)
	}
	return f
}

func (e *trustEnv) grant(server *model.TrustedServer, credential *model.AgentCredential) (*model.TemporaryGrant, string) {
	e.t.Helper()
	token, hash, hint := auth.NewToken(temporaryTokenPrefix)
	g := &model.TemporaryGrant{ID: store.NewID(), UserID: credential.OwnerUserID, CredentialID: credential.ID, ServerID: server.ID, IssuedBy: e.admin.ID, TokenHash: hash, TokenHint: hint}
	if err := e.st.IssueTemporaryGrant(e.ctx, g); err != nil {
		e.t.Fatal(err)
	}
	// 传入任意到期时间都必须被服务端固定为300秒。
	if g.ExpiresAt.Sub(g.IssuedAt) != model.TemporaryGrantTTL {
		e.t.Fatalf("签发期限未固定300秒：%v", g.ExpiresAt.Sub(g.IssuedAt))
	}
	return g, token
}
func (e *trustEnv) jsonRequest(method, path, token string, value any) (int, string) {
	e.t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		e.t.Fatal(err)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, strings.NewReader(string(raw)))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}
func (e *trustEnv) verify(serverToken, temporary string, want int, reason string) {
	e.t.Helper()
	status, body := e.jsonRequest("POST", "/api/v1/service/temporary-credentials/introspect", serverToken, map[string]string{"temporary_credential": temporary})
	if status != want || reason != "" && !strings.Contains(body, reason) {
		e.t.Fatalf("核验状态=%d，期望%d，原因%s，响应%s", status, want, reason, body)
	}
	if status != 200 && strings.Contains(body, e.person.ID) {
		e.t.Fatal("拒绝响应泄露了主体身份")
	}
}
func (e *trustEnv) ban(kind, user, credential, server, environment string) *model.WorkBan {
	e.t.Helper()
	b := &model.WorkBan{ID: store.NewID(), Kind: kind, Name: "测试规则", UserID: user, CredentialID: credential, ServerID: server, Environment: environment, Reason: "测试封禁", CreatedBy: e.admin.ID, StartsAt: e.st.Now()}
	if err := e.st.SaveWorkBan(e.ctx, b, false); err != nil {
		e.t.Fatal(err)
	}
	return b
}

func TestTrustIsolationAndLiveRevocation(t *testing.T) {
	e := newTrustEnv(t)
	g, temporary := e.grant(e.server, e.credential)
	e.verify(e.serverToken, temporary, 200, `"active":true`)
	_, otherKey := e.makeServer("其他服务", "https://other.example.test")
	e.verify(otherKey, temporary, 403, "grant_scope_mismatch")
	e.verify(e.agentToken, temporary, 401, "unauthorized")
	e.verify(e.serverToken, e.agentToken, 403, "credential_invalid")
	if err := e.st.RevokeTemporaryGrant(e.ctx, g.ID, e.admin.ID, ""); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, temporary, 403, "grant_revoked")
	client := newHTTPClient(t, e.ts.URL)
	if resp, _ := client.apiGet("/agent/v1/me", e.agentToken); resp.StatusCode != 200 {
		t.Fatal("撤销临时授信不应撤销原始凭证")
	}
	_, temporary = e.grant(e.server, e.credential)
	_, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	if err := e.st.RotateAgentCredentialToken(e.ctx, e.credential.ID, e.person.ID, hash, hint); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, temporary, 403, "parent_credential_invalid")
}

func TestTrustGlobalBansPreserveHumanAccess(t *testing.T) {
	e := newTrustEnv(t)
	_, temporary := e.grant(e.server, e.credential)
	b := e.ban("person", e.person.ID, "", "", "")
	e.verify(e.serverToken, temporary, 403, "person_banned")
	c := newHTTPClient(t, e.ts.URL)
	if response, body := c.apiGet("/api/v1/agent/me", e.agentToken); response.StatusCode != 403 || !strings.Contains(body, "person_banned") {
		t.Fatal("旧Agent入口未执行全局封人")
	}
	c.loginViaWeb(e.person.Username, testPassword)
	for _, path := range []string{"/", "/square", "/agents", "/servers", "/trust", "/audit"} {
		if r := c.get(path); r.StatusCode != 200 {
			t.Fatalf("人员封禁影响真人页面%s: %d", path, r.StatusCode)
		}
	}
	_, newToken := e.seedCredential(e.person, "封禁后新建")
	if r, _ := c.apiGet("/agent/v1/me", newToken); r.StatusCode != 403 {
		t.Fatal("新凭证绕过人员封禁")
	}
	if err := e.st.ReleaseWorkBan(e.ctx, b.ID, e.admin.ID); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, temporary, 200, "")
	b = e.ban("credential", e.person.ID, e.credential.ID, "", "")
	if r, _ := c.apiGet("/agent/v1/me", newToken); r.StatusCode != 200 {
		t.Fatal("封一个凭证影响了其他凭证")
	}
	rotated, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	if err := e.st.RotateAgentCredentialToken(e.ctx, e.credential.ID, e.person.ID, hash, hint); err != nil {
		t.Fatal(err)
	}
	if r, body := c.apiGet("/agent/v1/me", rotated); r.StatusCode != 403 || !strings.Contains(body, "credential_banned") {
		t.Fatal("轮换绕过稳定记录封禁")
	}
	if err := e.st.ReleaseWorkBan(e.ctx, b.ID, e.admin.ID); err != nil {
		t.Fatal(err)
	}
}

func TestTrustConditionalScopeAndExpiry(t *testing.T) {
	e := newTrustEnv(t)
	_, temporary := e.grant(e.server, e.credential)
	other, key := e.makeServer("其他Server", "https://conditional.example.test")
	_, otherTemporary := e.grant(other, e.credential)
	b := e.ban("condition", e.person.ID, "", e.server.ID, "生产")
	e.verify(e.serverToken, temporary, 403, "conditional_banned")
	e.verify(key, otherTemporary, 200, "")
	b.ExpiresAt = e.st.Now().Add(30 * time.Second)
	if err := e.st.SaveWorkBan(e.ctx, b, true); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(30)
	e.verify(e.serverToken, temporary, 200, "")
	e.clock.Add(3600)
	e.verify(e.serverToken, temporary, 403, "grant_not_effective")
}

func TestTrustHolidayCountdownUnlockAndAutoEnd(t *testing.T) {
	e := newTrustEnv(t)
	_, temporary := e.grant(e.server, e.credential)
	p := &model.HolidayPlan{ID: store.NewID(), CreatedBy: e.admin.ID, Reason: "节假日", TriggerAt: e.st.Now(), EndsAt: e.st.Now().Add(120 * time.Second)}
	if err := e.st.CreateHoliday(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(9)
	e.verify(e.serverToken, temporary, 200, "")
	e.clock.Add(1)
	e.verify(e.serverToken, temporary, 403, "holiday_lockdown")
	admin := newHTTPClient(t, e.ts.URL)
	admin.loginViaWeb(e.admin.Username, testPassword)
	admin.refreshCSRF("/trust")
	body := admin.getBody("/trust")
	if !strings.Contains(body, `inert class="trust-grey"`) || !strings.Contains(body, "解锁节假日封网") {
		t.Fatal("页面未锁定")
	}
	if admin.get("/servers").StatusCode != 200 {
		t.Fatal("节假日影响其他页面")
	}
	if r, _ := admin.postForm("/trust/grants", url.Values{}); r.StatusCode != 423 {
		t.Fatal("直接提交绕过节假日锁定")
	}
	if r, _ := admin.postForm("/trust/holiday/unlock", url.Values{"password": {"wrong"}}); r.StatusCode != 403 {
		t.Fatal("错误密码解锁")
	}
	e.verify(e.serverToken, temporary, 403, "holiday_lockdown")
	b := e.ban("person", e.person.ID, "", "", "")
	if r, _ := admin.postForm("/trust/holiday/unlock", url.Values{"password": {testUnlockPassword}}); r.StatusCode != 303 {
		t.Fatalf("密码解锁失败%d", r.StatusCode)
	}
	e.verify(e.serverToken, temporary, 403, "person_banned")
	if err := e.st.ReleaseWorkBan(e.ctx, b.ID, e.admin.ID); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, temporary, 200, "")
	e.clock.Add(1)
	next := &model.HolidayPlan{ID: store.NewID(), CreatedBy: e.admin.ID, Reason: "第二个计划", TriggerAt: e.st.Now(), EndsAt: e.st.Now().Add(30 * time.Second)}
	if err := e.st.CreateHoliday(e.ctx, next); err != nil {
		t.Fatal(err)
	}
	overlap := *next
	overlap.ID = store.NewID()
	if err := e.st.CreateHoliday(e.ctx, &overlap); err != store.ErrConflict {
		t.Fatal("允许重叠节假日计划")
	}
	e.clock.Add(10)
	e.verify(e.serverToken, temporary, 403, "holiday_lockdown")
	// 新Store模拟重启，不依赖浏览器或后台计时任务解封。
	e.st = store.NewWithClock(e.st.DB(), func() time.Time { return time.Unix(e.clock.Load(), 0) })
	e.srv.store = e.st
	e.clock.Add(20)
	e.verify(e.serverToken, temporary, 200, "")
	if strings.Contains(admin.getBody("/trust"), `inert class="trust-grey"`) {
		t.Fatal("到期页面未恢复")
	}
}

// TestTrustUnifiedAccessAndManagementCSRF 验证 v1 统一使用资格：
// 普通有效用户可见并可自助使用已启用入口；登记、轮换、签发管理等管理资格不受影响。
func TestTrustUnifiedAccessAndManagementCSRF(t *testing.T) {
	e := newTrustEnv(t)
	extra, _ := e.makeServer("受管服务", "https://unified.example.test")
	user := newHTTPClient(t, e.ts.URL)
	user.loginViaWeb(e.person.Username, testPassword)
	user.refreshCSRF("/agents")
	// 使用资格：普通用户可见全部已接入Server，不再有仅管理员可见的入口。
	if !strings.Contains(user.getBody("/servers"), extra.Name) || user.get("/servers/"+extra.ID).StatusCode != 200 {
		t.Fatal("普通用户看不见已接入Server")
	}
	// 使用资格：其名下有效Agent可自助签发该入口的临时凭证。
	status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": extra.ID, "target_origin": extra.Origin})
	if status != 201 {
		t.Fatal("普通用户Agent自助签发失败", status, body)
	}
	// 管理资格：签发管理页、Server登记与轮换仍仅管理员可操作。
	if r, _ := user.postForm("/trust/grants", url.Values{}); r.StatusCode != 403 {
		t.Fatal("普通用户越权签发")
	}
	if r, _ := user.do("POST", "/servers", url.Values{}, ""); r.StatusCode != 403 {
		t.Fatal("普通用户越权登记Server")
	}
	admin := newHTTPClient(t, e.ts.URL)
	admin.loginViaWeb(e.admin.Username, testPassword)
	admin.refreshCSRF("/trust")
	if r, _ := admin.do("POST", "/servers", url.Values{}, ""); r.StatusCode != 403 {
		t.Fatal("缺失CSRF被接受")
	}
	// 伪造超长到期时间的旧表单字段被忽略，期限仍由服务端固定为300秒。
	response, body := admin.postForm("/trust/grants", url.Values{"user_id": {e.person.ID}, "credential_id": {e.credential.ID}, "server_id": {extra.ID}, "expires_at": {e.st.Now().Add(24 * time.Hour).In(beijing).Format("2006-01-02T15:04:05")}})
	if response.StatusCode != 200 || !strings.Contains(body, temporaryTokenPrefix) || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("管理员签发失败%d", response.StatusCode)
	}
	if strings.Contains(user.getBody("/trust"), temporaryTokenPrefix+"A") {
		t.Fatal("列表泄露临时凭证原文")
	}
	grants, err := e.st.ListTemporaryGrants(e.ctx, e.person.ID)
	if err != nil || len(grants) == 0 {
		t.Fatal("签发记录缺失", err)
	}
	for _, g := range grants {
		if g.ExpiresAt.Sub(g.IssuedAt) != model.TemporaryGrantTTL {
			t.Fatal("网页签发未固定300秒")
		}
	}
	if r := user.get("/trust/grants/" + grants[0].ID); r.StatusCode != 200 {
		t.Fatal("无法查看本人授信详情")
	}
	other := e.seedUser("other_reader", "其他人")
	otherCred, _ := e.seedCredential(other, "其他凭证")
	response, _ = admin.postForm("/trust/grants", url.Values{"user_id": {e.person.ID}, "credential_id": {otherCred.ID}, "server_id": {extra.ID}})
	if response.StatusCode != 422 {
		t.Fatal("接受人员与凭证归属不匹配")
	}
}

// TestTrustFixedGrantDuration 固定300秒收口：新签发、边界、伪造与存量长授信。
func TestTrustFixedGrantDuration(t *testing.T) {
	e := newTrustEnv(t)
	// expires_in 兼容字段只接受省略、0或300；其余（含86400、299）拒绝。
	if status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "expires_in": 86400}); status != 422 || !strings.Contains(body, "invalid_expiry") {
		t.Fatal("24小时时长未被拒绝", status, body)
	}
	if status, _ := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "expires_in": 299}); status != 422 {
		t.Fatal("自选299秒未被拒绝")
	}
	status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "expires_in": 300})
	if status != 201 {
		t.Fatal(status, body)
	}
	var issued struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(body), &issued); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"expires_in":300`) {
		t.Fatal("响应未声明固定300秒")
	}
	if delta := issued.ExpiresAt.Sub(e.st.Now()); delta != model.TemporaryGrantTTL {
		t.Fatalf("签发期限=%v，期望300秒", delta)
	}
	var result struct {
		TemporaryCredential string `json:"temporary_credential"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatal(err)
	}
	temporary := result.TemporaryCredential
	// 边界：签发后299秒仍可核验；到300秒立即拒绝，无宽限期。
	e.clock.Add(299)
	e.verify(e.serverToken, temporary, 200, "")
	e.clock.Add(1)
	e.verify(e.serverToken, temporary, 403, "grant_not_effective")
	// 过期后重新申请得到新凭证，旧凭证不恢复。
	status, body = e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin})
	if status != 201 {
		t.Fatal("省略expires_in签发失败", status, body)
	}
	result.TemporaryCredential = ""
	if err := json.Unmarshal([]byte(body), &result); err != nil || result.TemporaryCredential == "" {
		t.Fatal(err)
	}
	e.verify(e.serverToken, temporary, 403, "grant_not_effective")
	e.verify(e.serverToken, result.TemporaryCredential, 200, "")
	// 存量长授信收口：历史记录保存了24小时到期时间，核验只承认签发后300秒。
	legacyToken, legacyHash, legacyHint := auth.NewToken(temporaryTokenPrefix)
	at := e.st.Now()
	if _, err := e.st.DB().Exec(`INSERT INTO temporary_grants(id,user_id,credential_id,server_id,parent_token_hash,target_origin,token_hash,token_hint,issued_by,issued_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		store.NewID(), e.person.ID, e.credential.ID, e.server.ID, e.credential.TokenHash, e.server.Origin, legacyHash, legacyHint, e.admin.ID, at.Unix(), at.Add(86400*time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	shortToken, shortHash, shortHint := auth.NewToken(temporaryTokenPrefix)
	if _, err := e.st.DB().Exec(`INSERT INTO temporary_grants(id,user_id,credential_id,server_id,parent_token_hash,target_origin,token_hash,token_hint,issued_by,issued_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		store.NewID(), e.person.ID, e.credential.ID, e.server.ID, e.credential.TokenHash, e.server.Origin, shortHash, shortHint, e.admin.ID, at.Unix(), at.Add(60*time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, legacyToken, 200, "")
	e.verify(e.serverToken, shortToken, 200, "")
	e.clock.Add(61)
	e.verify(e.serverToken, shortToken, 403, "grant_not_effective")
	e.verify(e.serverToken, legacyToken, 200, "")
	e.clock.Add(240) // 距签发301秒
	e.verify(e.serverToken, legacyToken, 403, "grant_not_effective")
	// 父凭证、封禁等核验不因固定300秒退化：撤销仍即时生效。
	if err := e.st.RevokeTemporaryGrant(e.ctx, func() string {
		grants, err := e.st.ListTemporaryGrants(e.ctx, e.person.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range grants {
			if g.TokenHash == legacyHash {
				return g.ID
			}
		}
		t.Fatal("未找到存量授信")
		return ""
	}(), e.admin.ID, ""); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, legacyToken, 403, "grant_revoked")
}

// TestTrustFieldGroupsLifecycle 变量编组申报闭环：登记、校验、快照、隔离与核验回传。
func TestTrustFieldGroupsLifecycle(t *testing.T) {
	e := newTrustEnv(t)
	publish := e.makeGroup(e.server, "发布编组", `{"fields":[{"key":"ENV","label":"环境","type":"enum","options":["dev","test","prod"],"required":true},{"key":"project","label":"项目名称","type":"string","max_len":64}]}`)
	e.makeGroup(e.server, "查询编组", `{"fields":[{"key":"mode","type":"enum","options":["fast","full"]}]}`)
	other, otherKey := e.makeServer("无编组服务", "https://plain.example.test")
	stranger, _ := e.makeServer("编组所属服务", "https://stranger.example.test")
	strangerGroup := e.makeGroup(stranger, "别家编组", `{"fields":[{"key":"zone","type":"enum","options":["a","b"],"required":true}]}`)

	// Agent API 可见编组定义。
	_, body := e.jsonRequest("GET", "/agent/v1/trusted-services", e.agentToken, nil)
	if !strings.Contains(body, `"field_groups"`) || !strings.Contains(body, "发布编组") || !strings.Contains(body, `"ENV"`) {
		t.Fatal("服务列表未暴露编组定义")
	}
	// 合法申报值签发成功，核验回传冻结的变量。
	status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": publish.ID, "field_values": map[string]string{"ENV": "prod", "project": "订单服务"}})
	if status != 201 {
		t.Fatal(status, body)
	}
	var issued struct {
		TemporaryCredential string `json:"temporary_credential"`
	}
	if err := json.Unmarshal([]byte(body), &issued); err != nil {
		t.Fatal(err)
	}
	grouped := issued.TemporaryCredential
	e.verify(e.serverToken, grouped, 200, `"ENV":"prod"`)
	e.verify(e.serverToken, grouped, 200, `"values"`)

	// 非法申报被明确拒绝：错误枚举、缺必填、未知键、错误类型。
	bad := func(values map[string]any) int {
		status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": publish.ID, "field_values": values})
		if status >= 500 {
			t.Fatal("校验失败变成服务错误", status, body)
		}
		return status
	}
	if bad(map[string]any{"ENV": "staging"}) != 422 {
		t.Fatal("错误枚举未被拒绝")
	}
	if bad(map[string]any{"project": "只有字符串"}) != 422 {
		t.Fatal("缺必填未被拒绝")
	}
	if bad(map[string]any{"ENV": "prod", "extra": "未知键"}) != 422 {
		t.Fatal("未知键未被拒绝")
	}
	if status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": publish.ID, "field_values": map[string]any{"ENV": 1}}); status != 422 {
		t.Fatal("错误类型未被拒绝", status, body)
	}
	// 不属于该Server的编组、空编组带值都被拒绝。
	if status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": strangerGroup.ID, "field_values": map[string]string{"zone": "a"}}); status != 422 || !strings.Contains(body, "invalid_field_group") {
		t.Fatal("别家编组未被拒绝", status, body)
	}
	if status, _ := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_values": map[string]string{"ENV": "prod"}}); status != 422 {
		t.Fatal("无编组携带申报值未被拒绝")
	}
	// 编组必填时省略申报值同样拒绝。
	if status, _ := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": publish.ID}); status != 422 {
		t.Fatal("必填编组缺申报值未被拒绝")
	}

	// 定义后改不影响已签发凭证：直接改库模拟维护者变更定义。
	if _, err := e.st.DB().Exec(`UPDATE server_field_groups SET definition=? WHERE id=?`, `{"fields":[{"key":"ENV","type":"enum","options":["dev"],"required":true}]}`, publish.ID); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, grouped, 200, `"ENV":"prod"`)
	e.verify(e.serverToken, grouped, 200, `"options":["dev","test","prod"]`)

	// 跨Server不能串用：该凭证在别家Server核验失败且不回传变量。
	e.verify(otherKey, grouped, 403, "grant_scope_mismatch")
	// 无编组Server照常签发与核验，成功响应不包含field_group。
	status, body = e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": other.ID, "target_origin": other.Origin})
	if status != 201 {
		t.Fatal(status, body)
	}
	issued.TemporaryCredential = ""
	if err := json.Unmarshal([]byte(body), &issued); err != nil {
		t.Fatal(err)
	}
	status, body = e.jsonRequest("POST", "/api/v1/service/temporary-credentials/introspect", otherKey, map[string]string{"temporary_credential": issued.TemporaryCredential})
	if status != 200 || strings.Contains(body, "field_group") {
		t.Fatal("无编组核验响应异常", status, body)
	}
	// 重启读取：真实关闭并重开数据库文件，验证编组快照与申报值持久化。
	if err := e.st.DB().Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := database.Open(e.srv.cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	e.st = store.NewWithClock(reopened, func() time.Time { return time.Unix(e.clock.Load(), 0) })
	e.srv.store = e.st
	e.verify(e.serverToken, grouped, 200, `"ENV":"prod"`)
	e.verify(e.serverToken, grouped, 200, `"values"`)

	// 管理页登记编组与管理员网页申报签发。
	admin := newHTTPClient(t, e.ts.URL)
	admin.loginViaWeb(e.admin.Username, testPassword)
	admin.refreshCSRF("/servers/" + other.ID)
	if r, _ := admin.postForm("/servers/"+other.ID+"/groups", url.Values{"name": {"网页编组"}, "description": {"说明"}, "definition": {`{"fields":[{"key":"ENV","type":"enum","options":["dev","test","prod"],"required":true}]}`}}); r.StatusCode != 303 {
		t.Fatal("网页登记编组失败")
	}
	if !strings.Contains(admin.getBody("/servers/"+other.ID), "网页编组") {
		t.Fatal("编组未展示")
	}
	groups, err := e.st.ListFieldGroups(e.ctx, other.ID)
	if err != nil || len(groups) != 1 {
		t.Fatal("编组保存失败", err)
	}
	admin.refreshCSRF("/trust")
	if r, body := admin.postForm("/trust/grants", url.Values{"user_id": {e.person.ID}, "credential_id": {e.credential.ID}, "server_id": {other.ID}, "field_group_id": {groups[0].ID}, "field_values": {`{"ENV":"test"}`}}); r.StatusCode != 200 || !strings.Contains(body, temporaryTokenPrefix) {
		t.Fatal("管理员网页申报签发失败", r.StatusCode, body)
	}
	// 非法定义被拒绝。
	admin.refreshCSRF("/servers/" + other.ID)
	if r, _ := admin.postForm("/servers/"+other.ID+"/groups", url.Values{"name": {"坏编组"}, "definition": {`{"fields":[{"key":"X","type":"checkbox"}]}`}}); r.StatusCode != 422 {
		t.Fatal("非法定义未被拒绝")
	}
	user := newHTTPClient(t, e.ts.URL)
	user.loginViaWeb(e.person.Username, testPassword)
	user.refreshCSRF("/servers/" + other.ID)
	if r, _ := user.postForm("/servers/"+other.ID+"/groups", url.Values{"name": {"越权"}, "definition": {`{"fields":[{"key":"A","type":"string"}]}`}}); r.StatusCode != 403 {
		t.Fatal("普通用户越权登记编组")
	}
	// 过期后核验不再返回可通行状态与变量（时钟以秒为单位推进301秒）。
	e.clock.Add(int64(model.TemporaryGrantTTL/time.Second) + 1)
	grants, err := e.st.ListTemporaryGrants(e.ctx, e.person.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range grants {
		code, err := e.st.GrantDenial(e.ctx, g)
		if err != nil {
			t.Fatal(err)
		}
		if code != "grant_not_effective" {
			t.Fatalf("过期授信仍可通行：%s code=%s", g.ID, code)
		}
	}
	t.Log("编组登记、申报校验、快照隔离、跨Server隔离与过期收口均通过")
}

func TestTrustGrantAPIAndIndependentPagination(t *testing.T) {
	e := newTrustEnv(t)
	status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "expires_in": 300})
	if status != 201 {
		t.Fatal(status, body)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, temporaryHeader) || strings.Contains(body, "token_type") {
		t.Fatal("没有使用专用请求头协议")
	}
	if result["expires_in"] != float64(300) {
		t.Fatal("响应有效期不是300秒")
	}
	e.verify(e.serverToken, result["temporary_credential"].(string), 200, "")
	for i := 0; i < 12; i++ {
		e.grant(e.server, e.credential)
		e.ban("person", e.admin.ID, "", "", "") /* 管理员自身工作封禁不阻止其真人操作。 */
	}
	admin := newHTTPClient(t, e.ts.URL)
	admin.loginViaWeb(e.admin.Username, testPassword)
	response, body := admin.do("GET", "/trust?grants_page=2&people_page=2&credentials_page=1", nil, "")
	if response.StatusCode != 200 || !strings.Contains(body, "正在工作凭证清单") || !strings.Contains(body, "封禁人员清单") || !strings.Contains(body, "封禁AI凭证清单") || !strings.Contains(body, "条件封禁清单") {
		t.Fatal("清单渲染不完整")
	}
	if !strings.Contains(body, "grants_page=2") || !strings.Contains(body, "people_page=2") || !strings.Contains(body, "第 2 / 2 页") {
		t.Fatal("分页没有保留其他清单状态")
	}
	if strings.Contains(body, e.server.TokenHash) || strings.Contains(body, e.credential.TokenHash) {
		t.Fatal("管理页面泄露内部凭证摘要")
	}
	t.Log(fmt.Sprintf("签发与核验成功，四张独立分页清单正常"))
}

func TestTrustOriginalBusinessAuthAndEveryRequest(t *testing.T) {
	e := newTrustEnv(t)
	grant, temporary := e.grant(e.server, e.credential)
	var callbacks atomic.Int64
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer original-business-token" || r.Header.Get("Cookie") != "session=original-session" {
			w.WriteHeader(401)
			return
		}
		values := r.Header.Values(temporaryHeader)
		if len(values) != 1 || values[0] == "" || strings.ContainsAny(values[0], " ,\t\r\n") {
			w.WriteHeader(400)
			return
		}
		callbacks.Add(1)
		status, _ := e.jsonRequest("POST", "/api/v1/service/temporary-credentials/introspect", e.serverToken, map[string]string{"temporary_credential": values[0]})
		w.WriteHeader(status)
	}))
	defer service.Close()
	request := func(want int) {
		t.Helper()
		req, _ := http.NewRequest("GET", service.URL, nil)
		req.Header.Set("Authorization", "Bearer original-business-token")
		req.Header.Set("Cookie", "session=original-session")
		req.Header.Set(temporaryHeader, temporary)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("业务链路状态%d，期望%d", resp.StatusCode, want)
		}
	}
	request(200)
	if err := e.st.RevokeTemporaryGrant(e.ctx, grant.ID, e.admin.ID, ""); err != nil {
		t.Fatal(err)
	}
	request(403)
	if callbacks.Load() != 2 {
		t.Fatal("第二次业务请求未重新回调核验")
	}
}

func TestTrustServerChangesAndCredentialRotation(t *testing.T) {
	e := newTrustEnv(t)
	_, temporary := e.grant(e.server, e.credential)
	e.server.Status = "disabled"
	if err := e.st.SaveTrustedServer(e.ctx, e.server, false); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, temporary, 403, "server_disabled")
	e.server.Status = "active"
	e.server.Origin = "https://changed.example.test"
	if err := e.st.SaveTrustedServer(e.ctx, e.server, false); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, temporary, 403, "grant_revoked")
	_, temporary = e.grant(e.server, e.credential)
	next, hash, hint := auth.NewToken(serviceTokenPrefix)
	if err := e.st.RotateServerKey(e.ctx, e.server.ID, hash, hint); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, temporary, 401, "unauthorized")
	e.verify(next, temporary, 200, "")
	e.server.Environment = "测试"
	if err := e.st.SaveTrustedServer(e.ctx, e.server, false); err != nil {
		t.Fatal(err)
	}
	e.verify(next, temporary, 403, "grant_revoked")
	e.server.Environment = "生产"
	if err := e.st.SaveTrustedServer(e.ctx, e.server, false); err != nil {
		t.Fatal(err)
	}
	e.verify(next, temporary, 403, "grant_revoked")
	var rawCount int
	if err := e.st.DB().QueryRow(`SELECT COUNT(*) FROM temporary_grants WHERE token_hash=?`, temporary).Scan(&rawCount); err != nil || rawCount != 0 {
		t.Fatal("数据库保存了临时凭证原文")
	}
}

// TestTrustDiscoveryDrivesIssuance 端到端闭环：只消费服务发现响应选择编组，
// 申请参数不使用夹具创建时的编组 ID；申报值合法项也取自发现返回的定义。
func TestTrustDiscoveryDrivesIssuance(t *testing.T) {
	e := newTrustEnv(t)
	e.makeGroup(e.server, "发布编组", `{"fields":[{"key":"ENV","label":"环境","type":"enum","options":["dev","test","prod"],"required":true},{"key":"project","label":"项目名称","type":"string","max_len":64}]}`)
	_, body := e.jsonRequest("GET", "/agent/v1/trusted-services", e.agentToken, nil)
	var listing struct {
		Servers []struct {
			TargetOrigin string `json:"target_origin"`
			FieldGroups  []struct {
				GroupID    string          `json:"group_id"`
				Name       string          `json:"name"`
				Definition json.RawMessage `json:"definition"`
			} `json:"field_groups"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(body), &listing); err != nil {
		t.Fatal(err)
	}
	var discovered struct {
		GroupID string
		Options []string
	}
	for _, server := range listing.Servers {
		if server.TargetOrigin != e.server.Origin {
			continue
		}
		for _, group := range server.FieldGroups {
			if group.Name != "发布编组" {
				continue
			}
			var def struct {
				Fields []struct {
					Key     string   `json:"key"`
					Type    string   `json:"type"`
					Options []string `json:"options"`
				} `json:"fields"`
			}
			if err := json.Unmarshal(group.Definition, &def); err != nil {
				t.Fatal(err)
			}
			for _, field := range def.Fields {
				if field.Key == "ENV" && field.Type == "enum" {
					discovered.GroupID, discovered.Options = group.GroupID, field.Options
				}
			}
		}
	}
	if discovered.GroupID == "" {
		t.Fatal("发现响应缺少可直接用于签发的编组标识")
	}
	legal := false
	for _, option := range discovered.Options {
		if option == "prod" {
			legal = true
		}
	}
	if !legal {
		t.Fatal("发现返回的定义缺少合法枚举项")
	}
	status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": discovered.GroupID, "field_values": map[string]string{"ENV": "prod", "project": "发现驱动"}})
	if status != 201 {
		t.Fatal(status, body)
	}
	var issued struct {
		TemporaryCredential string `json:"temporary_credential"`
		FieldGroup          struct {
			GroupID string            `json:"group_id"`
			Name    string            `json:"name"`
			Values  map[string]string `json:"values"`
		} `json:"field_group"`
	}
	if err := json.Unmarshal([]byte(body), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.FieldGroup.GroupID != discovered.GroupID || issued.FieldGroup.Name != "发布编组" || issued.FieldGroup.Values["ENV"] != "prod" {
		t.Fatalf("签发响应编组信息不完整: %s", body)
	}
	e.verify(e.serverToken, issued.TemporaryCredential, 200, `"group_id":"`+discovered.GroupID+`"`)
	e.verify(e.serverToken, issued.TemporaryCredential, 200, `"project":"发现驱动"`)
}

// TestTrustOptionalGroupValueSemantics 区分省略、空对象与非法输入：
// 全部可选的编组可显式申报 {}；null／数字／布尔／对象／数组一律拒绝，
// API 与网页行为一致。
func TestTrustOptionalGroupValueSemantics(t *testing.T) {
	e := newTrustEnv(t)
	optional := e.makeGroup(e.server, "可选编组", `{"fields":[{"key":"note","type":"string","max_len":32}]}`)
	issue := func(raw json.RawMessage) int {
		e.t.Helper()
		payload := map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": optional.ID}
		if raw != nil {
			payload["field_values"] = raw
		}
		status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, payload)
		if status >= 500 {
			e.t.Fatalf("校验退化为服务错误 %d %s", status, body)
		}
		return status
	}
	if issue(json.RawMessage(`{}`)) != 201 {
		t.Fatal("全部可选编组的显式空对象被拒绝")
	}
	if issue(json.RawMessage(`{"note":"ok"}`)) != 201 {
		t.Fatal("合法字符串申报被拒绝")
	}
	for _, raw := range []string{`{"note":null}`, `{"note":1}`, `{"note":true}`, `{"note":{"a":"b"}}`, `{"note":["x"]}`, `{"unknown":"x"}`, `null`, `[1]`, `"text"`, `5`} {
		if issue(json.RawMessage(raw)) != 422 {
			t.Fatalf("非法申报 %s 未被拒绝", raw)
		}
	}
	// 省略 field_values 与空对象语义不同：选择编组时必须显式申报。
	if status, _ := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": optional.ID}); status != 422 {
		t.Fatal("省略申报值未被拒绝")
	}
	// 空对象凭证核验回传空 values；网页提交 {} 行为一致。
	admin := newHTTPClient(t, e.ts.URL)
	admin.loginViaWeb(e.admin.Username, testPassword)
	admin.refreshCSRF("/trust")
	if r, body := admin.postForm("/trust/grants", url.Values{"user_id": {e.person.ID}, "credential_id": {e.credential.ID}, "server_id": {e.server.ID}, "field_group_id": {optional.ID}, "field_values": {`{}`}}); r.StatusCode != 200 || !strings.Contains(body, temporaryTokenPrefix) {
		t.Fatal("网页空对象申报与API不一致")
	}
	status, body := e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]any{"service_id": e.server.ID, "target_origin": e.server.Origin, "field_group_id": optional.ID, "field_values": map[string]string{}})
	if status != 201 {
		t.Fatal(status, body)
	}
	var issued struct {
		TemporaryCredential string `json:"temporary_credential"`
	}
	if err := json.Unmarshal([]byte(body), &issued); err != nil {
		t.Fatal(err)
	}
	e.verify(e.serverToken, issued.TemporaryCredential, 200, `"values":{`)
}

// TestTrustFieldGroupDefinitionTrailingJunk 编组定义只接受一个完整 JSON 值：
// 尾随损坏字符或第二个值都拒绝，尾随空白不受影响。
func TestTrustFieldGroupDefinitionTrailingJunk(t *testing.T) {
	e := newTrustEnv(t)
	clean := `{"fields":[{"key":"ENV","type":"enum","options":["a"]}]}`
	save := func(definition string) error {
		return e.st.SaveFieldGroup(e.ctx, &model.FieldGroup{ID: store.NewID(), ServerID: e.server.ID, Name: "编组" + store.NewID()[:6], Definition: definition, CreatedBy: e.admin.ID})
	}
	if err := save(clean + "x"); err != store.ErrInvalidTrust {
		t.Fatal("尾随损坏字符被接受", err)
	}
	if err := save(clean + clean); err != store.ErrInvalidTrust {
		t.Fatal("尾随第二个JSON值被接受", err)
	}
	if err := save(clean + "  \n\t"); err != nil {
		t.Fatal("尾随空白不应被拒绝", err)
	}
	if err := save(clean); err != nil {
		t.Fatal(err)
	}
}

// TestTrustCrossServerDenialKeepsAuditChain 已知授信被其他Server核验时：
// 对外仍拒绝且不泄露主体，内部审计保留授信、父凭证与所属人关联，
// 并区分发起核验的Server与凭证绑定的Server；本人可在个人审计看到该事件。
func TestTrustCrossServerDenialKeepsAuditChain(t *testing.T) {
	e := newTrustEnv(t)
	g, temporary := e.grant(e.server, e.credential)
	other, otherKey := e.makeServer("其他核验方", "https://audit-chain.example.test")
	e.verify(otherKey, temporary, 403, "grant_scope_mismatch")
	find := func(logs []*model.AuditLog) *model.AuditLog {
		for _, log := range logs {
			if log.Event == "trust_verification_denied" && log.Reason == "grant_scope_mismatch" && strings.Contains(log.Detail, "grant_id="+g.ID) {
				return log
			}
		}
		return nil
	}
	global, err := e.st.ListAuditAdmin(e.ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	log := find(global)
	if log == nil {
		t.Fatal("跨Server拒绝未留下含授信关联的审计")
	}
	if log.SubjectUserID != e.person.ID || log.CredentialID != e.credential.ID {
		t.Fatal("审计缺少所属人或父凭证关联")
	}
	if !strings.Contains(log.Detail, "server_id="+other.ID) || !strings.Contains(log.Detail, "grant_server_id="+e.server.ID) {
		t.Fatal("审计未区分请求核验方与凭证绑定方:", log.Detail)
	}
	mine, err := e.st.ListAuditForUser(e.ctx, e.person.ID, 200)
	if err != nil {
		t.Fatal(err)
	}
	if find(mine) == nil {
		t.Fatal("个人审计无法关联该次跨Server尝试")
	}
}

// TestTrustHolidayBlocksAgentAPIIncludingForum 固定当前语义：节假日封网生效期间，
// Agent 接口整体被拒（含广场发言入口），永久凭证不豁免封网；政策是否调整待用户决定。
func TestTrustHolidayBlocksAgentAPIIncludingForum(t *testing.T) {
	e := newTrustEnv(t)
	client := newHTTPClient(t, e.ts.URL)
	if r, _ := client.apiGet("/agent/v1/me", e.agentToken); r.StatusCode != 200 {
		t.Fatal("封网前Agent接口不可用")
	}
	p := &model.HolidayPlan{ID: store.NewID(), CreatedBy: e.admin.ID, Reason: "节假日", TriggerAt: e.st.Now(), EndsAt: e.st.Now().Add(120 * time.Second)}
	if err := e.st.CreateHoliday(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(11)
	if r, body := client.apiGet("/agent/v1/me", e.agentToken); r.StatusCode != 403 || !strings.Contains(body, "holiday_lockdown") {
		t.Fatal("封网未阻断Agent身份接口", r.StatusCode, body)
	}
	if status, body := e.jsonRequest("POST", "/agent/v1/threads/nonexistent/floors", e.agentToken, map[string]string{"body": "x"}); status != 403 || !strings.Contains(body, "holiday_lockdown") {
		t.Fatal("封网未阻断广场发言入口", status, body)
	}
}
