package handler

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
)

// newTestToken 生成测试用新凭证三元组。
func newTestToken(prefix string) (raw, hash, hint string) {
	return auth.NewToken(prefix)
}

// Agent /me 正常返回且不泄露内部字段
func TestCredentialMe(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("gina", "吉娜")
	_, token := e.seedCredential(u, "gina-agent")

	resp, body := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/agent/me", token)
	if resp.StatusCode != 200 {
		t.Fatalf("agent/me 应 200，得到 %d: %s", resp.StatusCode, body)
	}
	for _, field := range []string{"owner_username", "owner_display_name", "agent_name"} {
		if !strings.Contains(body, field) {
			t.Fatalf("agent/me 缺少字段 %s: %s", field, body)
		}
	}
	for _, banned := range []string{"password_hash", "token_hash", "csrf"} {
		if strings.Contains(body, banned) {
			t.Fatalf("agent/me 不应暴露 %s: %s", banned, body)
		}
	}
}

// 无效/缺失凭证 → 401 JSON
func TestAgentAPIUnauthorized(t *testing.T) {
	e := newTestEnv(t)
	c := newHTTPClient(t, e.ts.URL)
	resp, body := c.apiGet("/api/v1/agent/me", "")
	if resp.StatusCode != 401 || !strings.Contains(body, `"code":"unauthorized"`) {
		t.Fatalf("缺失凭证应 401 JSON，得到 %d %s", resp.StatusCode, body)
	}
	resp, _ = c.apiGet("/api/v1/agent/me", "aad_agent_bogus")
	if resp.StatusCode != 401 {
		t.Fatalf("无效凭证应 401，得到 %d", resp.StatusCode)
	}
}

// 7. Service Token 不能冒充 Agent
func TestServiceTokenCannotActAsAgent(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("hank", "汉克")
	capability, svcToken := e.seedCapability(owner, "hank-cap")

	resp, _ := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/agent/me", svcToken)
	if resp.StatusCode != 401 {
		t.Fatalf("Service Token 访问 Agent API 应 401，得到 %d", resp.StatusCode)
	}
	resp, _ = newHTTPClient(t, e.ts.URL).apiGet("/api/v1/capabilities/"+capability.ID, svcToken)
	if resp.StatusCode != 401 {
		t.Fatalf("Service Token 查能力详情应 401，得到 %d", resp.StatusCode)
	}
}

// 8. Agent Token 不能冒充 Service Token
func TestAgentTokenCannotCallAuthorize(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("ivan", "伊万")
	_, agentToken := e.seedCredential(u, "ivan-agent")

	c := newHTTPClient(t, e.ts.URL)
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/service/authorize", strings.NewReader(`{"agent_token":"x"}`))
	req.Header.Set("Authorization", "Bearer "+agentToken)
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("Agent Token 调授权接口应 401，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// 9. 能力列表过滤无权访问的能力；10. 猜测能力 ID 不能绕过权限
func TestCapabilityListFilterAndDetail404(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	capability, _ := e.seedCapability(wangwu, "filter-cap")
	_, zhangsanToken := e.seedCredential(zhangsan, "z-agent")

	// team 模式下可见
	_, body := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/capabilities", zhangsanToken)
	if !strings.Contains(body, "filter-cap") {
		t.Fatalf("team 模式应可见能力: %s", body)
	}

	// 拉黑张三后列表不再返回
	if err := e.st.AddDeny(e.ctx, capability.ID, zhangsan.ID); err != nil {
		t.Fatal(err)
	}
	_, body = newHTTPClient(t, e.ts.URL).apiGet("/api/v1/capabilities", zhangsanToken)
	if strings.Contains(body, "filter-cap") {
		t.Fatalf("被拉黑后不应看到能力: %s", body)
	}
	// 详情同样 404（不泄露存在性）
	resp, _ := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/capabilities/"+capability.ID, zhangsanToken)
	if resp.StatusCode != 404 {
		t.Fatalf("被拉黑后详情应 404，得到 %d", resp.StatusCode)
	}
	// 随机 ID 也是 404
	resp, _ = newHTTPClient(t, e.ts.URL).apiGet("/api/v1/capabilities/nonexistent000", zhangsanToken)
	if resp.StatusCode != 404 {
		t.Fatalf("不存在的能力应 404，得到 %d", resp.StatusCode)
	}
}

// 11. Agent Token 轮换后旧 Token 失效
func TestAgentTokenRotation(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("jack", "杰克")
	credential, oldToken := e.seedCredential(u, "jack-agent")

	newRaw, newHash, newHint := newTestToken(auth.AgentTokenPrefix)
	if err := e.st.RotateAgentCredentialToken(e.ctx, credential.ID, u.ID, newHash, newHint); err != nil {
		t.Fatal(err)
	}
	resp, _ := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/agent/me", oldToken)
	if resp.StatusCode != 401 {
		t.Fatalf("旧 Agent Token 轮换后应 401，得到 %d", resp.StatusCode)
	}
	resp, _ = newHTTPClient(t, e.ts.URL).apiGet("/api/v1/agent/me", newRaw)
	if resp.StatusCode != 200 {
		t.Fatalf("新 Agent Token 应 200，得到 %d", resp.StatusCode)
	}
}

// 12. Agent 撤销后旧 Token 失效
func TestCredentialRevocation(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("kate", "凯特")
	credential, token := e.seedCredential(u, "kate-agent")
	if err := e.st.RevokeAgentCredential(e.ctx, credential.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	resp, _ := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/agent/me", token)
	if resp.StatusCode != 401 {
		t.Fatalf("撤销后旧 Token 应 401，得到 %d", resp.StatusCode)
	}
}

// 13. Service Token 轮换后旧 Token 失效；14. 能力 A 的 Service Token 不能用于能力 B
func TestServiceTokenRotationAndScoping(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("liam", "利亚姆")
	caller := e.seedUser("mia", "米娅")
	capA, svcA := e.seedCapability(owner, "cap-a")
	capB, svcB := e.seedCapability(owner, "cap-b")
	_, agentToken := e.seedCredential(caller, "mia-agent")

	// A、B 均可授权
	if code, out := e.authorize(svcA, agentToken); code != 200 || out["allowed"] != true {
		t.Fatalf("cap-a 授权应成功: %v", out)
	}
	if code, out := e.authorize(svcB, agentToken); code != 200 || out["allowed"] != true {
		t.Fatalf("cap-b 授权应成功: %v", out)
	}

	// 能力 A 的 Service Token 请求体携带 capability_id=B → 400
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v1/service/authorize",
		strings.NewReader(`{"agent_token":"`+agentToken+`","capability_id":"`+capB.ID+`"}`))
	req.Header.Set("Authorization", "Bearer "+svcA)
	resp, _ := newHTTPClient(t, e.ts.URL).http.Do(req)
	if resp.StatusCode != 400 {
		t.Fatalf("capability_id 与绑定能力不一致应 400，得到 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 轮换 A 的 Service Token：旧失效
	newRaw, newHash, newHint := newTestToken(auth.ServiceTokenPrefix)
	if err := e.st.RotateServiceToken(e.ctx, capA.ID, owner.ID, newHash, newHint); err != nil {
		t.Fatal(err)
	}
	if code, out := e.authorize(svcA, agentToken); code != 401 {
		t.Fatalf("旧 Service Token 应 401，得到 %d %v", code, out)
	}
	if code, out := e.authorize(newRaw, agentToken); code != 200 || out["allowed"] != true {
		t.Fatalf("新 Service Token 应正常授权: %v", out)
	}
	// B 不受影响
	if code, out := e.authorize(svcB, agentToken); code != 200 || out["allowed"] != true {
		t.Fatalf("cap-b 不应受 cap-a 轮换影响: %v", out)
	}
}

// 15. 黑名单对该用户的两个 Agent 同时生效（按真人账号授权主体）
func TestDenylistCoversAllCredentialsOfUser(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	lisi := e.seedUser("lisi", "李四")
	capability, svcToken := e.seedCapability(wangwu, "multi-cap")
	_, token1 := e.seedCredential(zhangsan, "张三-Agent-1")
	_, token2 := e.seedCredential(zhangsan, "张三-Agent-2")
	_, lisiToken := e.seedCredential(lisi, "李四-Agent")

	// 拉黑前：张三两个 Agent、李四 Agent 都允许
	for _, tk := range []string{token1, token2, lisiToken} {
		if code, out := e.authorize(svcToken, tk); code != 200 || out["allowed"] != true {
			t.Fatalf("拉黑前应允许: %v", out)
		}
	}
	// 拉黑张三（账号维度）
	if err := e.st.AddDeny(e.ctx, capability.ID, zhangsan.ID); err != nil {
		t.Fatal(err)
	}
	// 张三的两个 Agent 立即全部被拒，理由 user_blacklisted
	for _, tk := range []string{token1, token2} {
		code, out := e.authorize(svcToken, tk)
		if code != 200 || out["allowed"] != false || out["reason"] != "user_blacklisted" {
			t.Fatalf("拉黑后张三的每个 Agent 都应被拒: %v", out)
		}
	}
	// 李四不受影响
	if code, out := e.authorize(svcToken, lisiToken); code != 200 || out["allowed"] != true {
		t.Fatalf("李四应仍允许: %v", out)
	}
}

// 16. 凭证原文未存入数据库
func TestTokensNotStoredInPlaintext(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("nina", "妮娜")
	credential, agentToken := e.seedCredential(u, "nina-agent")
	capability, svcToken := e.seedCapability(u, "nina-cap")

	if credential.TokenHash == agentToken || credential.TokenHint == agentToken {
		t.Fatalf("Agent Token 原文不得入库")
	}
	if strings.Contains(credential.TokenHash, "aad_agent_") {
		t.Fatalf("Token 摘要不应包含原文前缀")
	}
	cred, err := e.st.GetServiceCredentialByCapability(e.ctx, capability.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cred.TokenHash == svcToken {
		t.Fatalf("Service Token 原文不得入库")
	}
	// 全表扫描兜底：任何列都不含原始 Token
	for _, table := range []string{"agents", "capability_service_credentials", "sessions", "audit_logs"} {
		rows, err := e.st.DB().Query("SELECT * FROM " + table)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			rows.Scan(ptrs...)
			for _, v := range vals {
				if s, ok := v.(string); ok && (s == agentToken || s == svcToken) {
					t.Fatalf("表 %s 中发现凭证原文", table)
				}
			}
		}
		rows.Close()
	}
}

// 用户被禁用后其 Agent Token 立即失效（含 API 401 与授权拒绝）
func TestDisabledUserCredentialsInvalid(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	_, svcToken := e.seedCapability(wangwu, "disable-cap")
	_, agentToken := e.seedCredential(zhangsan, "z-agent")

	// 禁用张三
	if err := e.st.SetUserStatus(e.ctx, zhangsan.ID, model.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	resp, _ := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/agent/me", agentToken)
	if resp.StatusCode != 401 {
		t.Fatalf("用户禁用后 Agent API 应 401，得到 %d", resp.StatusCode)
	}
	code, out := e.authorize(svcToken, agentToken)
	if code != 200 || out["allowed"] != false || out["reason"] != "user_disabled" {
		t.Fatalf("用户禁用后授权应拒绝 user_disabled: %v", out)
	}
}

// 能力停用后所有 Agent（含所有者）均不能发现或调用
func TestDisabledCapabilityBlocksAll(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	capability, svcToken := e.seedCapability(wangwu, "off-cap")
	_, ownerToken := e.seedCredential(wangwu, "owner-agent")

	// 停用能力
	if err := e.st.SetCapabilityStatus(e.ctx, capability.ID, wangwu.ID, model.StatusDisabled); err != nil {
		t.Fatal(err)
	}
	// 所有者自己的 Agent 也不能再发现
	_, body := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/capabilities", ownerToken)
	if strings.Contains(body, "off-cap") {
		t.Fatalf("能力停用后不应被发现: %s", body)
	}
	// 授权拒绝 capability_disabled
	if code, out := e.authorize(svcToken, ownerToken); code != 200 || out["reason"] != "capability_disabled" {
		t.Fatalf("停用能力授权应拒绝 capability_disabled: %v", out)
	}
}

// 白名单模式：仅白名单用户与所有者可访问
func TestAllowlistModeScoping(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	lisi := e.seedUser("lisi", "李四")
	capability, svcToken := e.seedCapability(wangwu, "allow-cap")
	_, zToken := e.seedCredential(zhangsan, "z-agent")
	_, lToken := e.seedCredential(lisi, "l-agent")
	_, ownerToken := e.seedCredential(wangwu, "w-agent")

	// 切白名单模式，仅加李四
	if err := e.st.SetAccessMode(e.ctx, capability.ID, wangwu.ID, model.AccessModeAllowlist); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddAllow(e.ctx, capability.ID, lisi.ID); err != nil {
		t.Fatal(err)
	}
	if code, out := e.authorize(svcToken, zToken); code != 200 || out["reason"] != "user_not_allowlisted" {
		t.Fatalf("非白名单用户应拒绝: %v", out)
	}
	if code, out := e.authorize(svcToken, lToken); code != 200 || out["allowed"] != true {
		t.Fatalf("白名单用户应允许: %v", out)
	}
	if code, out := e.authorize(svcToken, ownerToken); code != 200 || out["allowed"] != true {
		t.Fatalf("所有者应允许: %v", out)
	}
}

// 能力所有者不能被加入黑名单（Web 层校验）
func TestOwnerCannotBeDenylisted(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	capability, _ := e.seedCapability(wangwu, "self-deny-cap")

	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb("wangwu", testPassword)
	resp, _ := c.postForm("/capabilities/"+capability.ID+"/denylist/add", url.Values{"user_id": {wangwu.ID}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("所有者加黑名单应被拒绝并重定向，得到 %d", resp.StatusCode)
	}
	// 重定向后的页面应展示拒绝原因（Flash）
	page := c.getBody("/capabilities/" + capability.ID + "/access")
	if !strings.Contains(page, "不能把能力所有者") {
		t.Fatalf("应提示不能把所有者加入黑名单")
	}
	// 数据库层面也没有记录
	if denied, _ := e.st.IsDenied(e.ctx, capability.ID, wangwu.ID); denied {
		t.Fatalf("所有者不应进入黑名单")
	}
}

// 管理员不绕过能力访问策略（API 层验证）
func TestAdminAgentNoBypass(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	e.seedAdmin("root", "管理员")
	capability, svcToken := e.seedCapability(wangwu, "admin-cap")
	// 管理员名下的 Agent
	admin, err := e.st.GetUserByUsername(e.ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	_, adminToken := e.seedCredential(admin, "admin-agent")

	// 切白名单模式，管理员不在白名单
	if err := e.st.SetAccessMode(e.ctx, capability.ID, wangwu.ID, model.AccessModeAllowlist); err != nil {
		t.Fatal(err)
	}
	_, body := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/capabilities", adminToken)
	if strings.Contains(body, "admin-cap") {
		t.Fatalf("管理员不应绕过 allowlist: %s", body)
	}
	if code, out := e.authorize(svcToken, adminToken); code != 200 || out["allowed"] != false {
		t.Fatalf("管理员授权也应拒绝: %v", out)
	}
	_ = capability
}
