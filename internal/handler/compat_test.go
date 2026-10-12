package handler

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"agentpermit/internal/auth"
)

// 更名前签发的旧前缀 Token（aad_agent_ / aad_service_）必须继续可用：
// 验证只按 SHA-256 摘要查库，不检查前缀。
func TestLegacyPrefixTokensStillValid(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")

	// 用旧前缀生成 Agent Token（模拟更名前签发的存量凭证）
	legacyAgentToken, legacyHash, legacyHint := auth.NewToken(auth.LegacyAgentTokenPrefix)
	credential := mustSeedCredential(e, zhangsan.ID, "存量-Agent", legacyHash, legacyHint)
	_ = credential

	c := newHTTPClient(t, e.ts.URL)
	resp, _ := c.apiGet("/api/v1/agent/me", legacyAgentToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("旧前缀 Agent Token 应继续有效，得到 %d", resp.StatusCode)
	}

	// 用旧前缀生成 Service Token（模拟更名前创建的能力）
	legacySvcToken, svcHash, svcHint := auth.NewToken(auth.LegacyServiceTokenPrefix)
	capability := mustSeedCapability(e, wangwu.ID, "legacy-cap", svcHash, svcHint)
	_ = capability
	code, out := e.authorize(legacySvcToken, legacyAgentToken)
	if code != http.StatusOK || out["allowed"] != true {
		t.Fatalf("旧前缀 Service Token 授权应成功: %v", out)
	}
	code, out = e.authorize(legacySvcToken, legacyAgentToken)
	if code != http.StatusOK || out["capability_id"] != capability.ID {
		t.Fatalf("授权应绑定正确能力: %v", out)
	}
}

// 新签发凭证使用新前缀 ap_agent_ / ap_service_
func TestNewTokensUseNewPrefix(t *testing.T) {
	agentToken, _, _ := auth.NewToken(auth.AgentTokenPrefix)
	if !strings.HasPrefix(agentToken, "ap_agent_") {
		t.Fatalf("新 Agent Token 应使用 ap_agent_ 前缀: %s…", agentToken[:12])
	}
	svcToken, _, _ := auth.NewToken(auth.ServiceTokenPrefix)
	if !strings.HasPrefix(svcToken, "ap_service_") {
		t.Fatalf("新 Service Token 应使用 ap_service_ 前缀")
	}
}

// 更名前的会话 Cookie（aad_session）仍可识别，已有登录态不丢失
func TestLegacySessionCookieStillWorks(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("oscar", "奥斯卡")

	// 直接在数据库中造一个会话（等价于更名前登录留下的 Cookie）
	sessionToken := "aad_session_legacy_" + auth.NewRandomHex(32)
	csrf := auth.NewRandomHex(16)
	expires := time.Now().Add(time.Hour)
	if err := e.st.CreateSession(e.ctx, auth.HashToken(sessionToken), u.ID, csrf, expires); err != nil {
		t.Fatal(err)
	}

	// 只携带旧 Cookie 名访问控制台 → 应视为已登录（200，而非跳转登录）
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/", nil)
	req.Header.Set("Cookie", "aad_session="+sessionToken)
	resp, err := newHTTPClient(t, e.ts.URL).http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("旧会话 Cookie 应保持登录态，得到 %d", resp.StatusCode)
	}

	// 新 Cookie 名优先：ap_session 无效值 + aad_session 有效值 → 未登录
	req2, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/", nil)
	req2.Header.Set("Cookie", "ap_session=ap_session_bogus; aad_session="+sessionToken)
	resp2, err := newHTTPClient(t, e.ts.URL).http.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("新 Cookie 名应优先判定，无效新值应视为未登录，得到 %d", resp2.StatusCode)
	}
}
