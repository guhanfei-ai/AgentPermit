package handler

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"agentpermit/internal/demoservice"
	"agentpermit/internal/model"
)

// e2e 环境真实启动两个 httptest 服务：平台 + 独立机器服务，
// 验证 Agent → 独立服务 → 平台授权 → 允许/拒绝 → 业务结果 的完整链路。
type e2eEnv struct {
	platform *httptest.Server
	machine  *httptest.Server
	e        *testEnv
}

func newE2EEnv(t *testing.T, baseURL string, svcToken string) *e2eEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	machine := httptest.NewServer(demoservice.New(baseURL, svcToken, logger).Handler())
	t.Cleanup(machine.Close)
	return &e2eEnv{machine: machine}
}

func (e *e2eEnv) callMachine(agentToken, machineID string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, e.machine.URL+"/machines/"+machineID+"/spec", nil)
	req.Header.Set("Authorization", "Bearer "+agentToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// 完整链路：允许 → 拉黑立即拒绝 → 白名单模式 → 撤销凭证 → 机器不存在
func TestE2EFullChain(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")     // 能力提供者
	zhangsan := e.seedUser("zhangsan", "张三") // 调用者
	lisi := e.seedUser("lisi", "李四")         // 调用者
	capability, svcToken := e.seedCapability(wangwu, "machine-spec")
	_, zToken1 := e.seedCredential(zhangsan, "张三-Agent-1")
	_, zToken2 := e.seedCredential(zhangsan, "张三-Agent-2")
	lAgent, lToken := e.seedCredential(lisi, "李四-Agent")

	env := newE2EEnv(t, e.ts.URL, svcToken)

	// 1) 授权成功返回机器信息
	code, body := env.callMachine(zToken1, "machine-001")
	if code != 200 || !containsAll(body, `"cpu":"8 cores"`, `"os":"Ubuntu 22.04"`) {
		t.Fatalf("张三 Agent-1 应成功获取 machine-001: %d %s", code, body)
	}
	code, body = env.callMachine(zToken2, "machine-002")
	if code != 200 || !containsAll(body, `"cpu":"16 cores"`, `"os":"Rocky Linux 9"`) {
		t.Fatalf("张三 Agent-2 应成功获取 machine-002: %d %s", code, body)
	}
	code, body = env.callMachine(lToken, "machine-001")
	if code != 200 {
		t.Fatalf("李四应成功: %d %s", code, body)
	}

	// 2) 王五把张三加入黑名单 → 张三两个 Agent 立即 403，李四不受影响
	if err := e.st.AddDeny(e.ctx, capability.ID, zhangsan.ID); err != nil {
		t.Fatal(err)
	}
	code, body = env.callMachine(zToken1, "machine-001")
	if code != 403 || !containsAll(body, "user_blacklisted") {
		t.Fatalf("拉黑后张三 Agent-1 应 403 user_blacklisted: %d %s", code, body)
	}
	code, body = env.callMachine(zToken2, "machine-001")
	if code != 403 || !containsAll(body, "user_blacklisted") {
		t.Fatalf("拉黑后张三 Agent-2 应 403 user_blacklisted: %d %s", code, body)
	}
	code, _ = env.callMachine(lToken, "machine-001")
	if code != 200 {
		t.Fatalf("李四应仍成功: %d", code)
	}

	// 3) 切白名单模式仅加李四：李四成功，其他非所有者用户失败
	if err := e.st.SetAccessMode(e.ctx, capability.ID, wangwu.ID, model.AccessModeAllowlist); err != nil {
		t.Fatal(err)
	}
	if err := e.st.AddAllow(e.ctx, capability.ID, lisi.ID); err != nil {
		t.Fatal(err)
	}
	code, _ = env.callMachine(lToken, "machine-001")
	if code != 200 {
		t.Fatalf("白名单模式下李四应成功: %d", code)
	}
	// 张三还在黑名单（黑名单优先）；另找无关用户验证 not_allowlisted
	other := e.seedUser("wangmazi", "王麻子")
	_, otherToken := e.seedCredential(other, "wmz-agent")
	code, body = env.callMachine(otherToken, "machine-001")
	if code != 403 || !containsAll(body, "user_not_allowlisted") {
		t.Fatalf("白名单模式下无关用户应 403 user_not_allowlisted: %d %s", code, body)
	}

	// 4) 撤销李四的 Agent：原 Token 不能再发现能力或调用服务
	if err := e.st.RevokeAgentCredential(e.ctx, lAgent.ID, lisi.ID); err != nil {
		t.Fatal(err)
	}
	resp, apiBody := newHTTPClient(t, e.ts.URL).apiGet("/api/v1/capabilities", lToken)
	if resp.StatusCode != 401 {
		t.Fatalf("撤销后 Agent API 应 401，得到 %d %s", resp.StatusCode, apiBody)
	}
	code, body = env.callMachine(lToken, "machine-001")
	if code != 401 {
		t.Fatalf("撤销后调用服务应 401: %d %s", code, body)
	}

	// 5) 机器不存在：授权成功后 404
	code, _ = env.callMachine(zToken1, "machine-999") // 张三已被拉黑，先换所有者验证
	_ = code
	_, ownerToken := e.seedCredential(wangwu, "owner-agent")
	code, body = env.callMachine(ownerToken, "machine-999")
	if code != 404 || !containsAll(body, "machine_not_found") {
		t.Fatalf("不存在的机器应在授权成功后 404: %d %s", code, body)
	}

	// 6) 无 Agent Token → 401
	req, _ := http.NewRequest(http.MethodGet, env.machine.URL+"/machines/machine-001/spec", nil)
	resp2, _ := http.DefaultClient.Do(req)
	if resp2.StatusCode != 401 {
		t.Fatalf("缺少 Agent Token 应 401，得到 %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

// 17. 平台不可用时 fail closed：Demo 服务返回 503，不返回机器信息
func TestE2EFailClosed(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	_, svcToken := e.seedCapability(wangwu, "fail-closed-cap")
	_, agentToken := e.seedCredential(wangwu, "owner-agent")

	// 指向不可达的平台地址
	env := newE2EEnv(t, "http://127.0.0.1:1", svcToken)
	code, body := env.callMachine(agentToken, "machine-001")
	if code != 503 || containsAll(body, "8 cores") {
		t.Fatalf("平台不可用应 503 且不泄露机器信息: %d %s", code, body)
	}

	// 平台返回 500 时同样 fail closed：用一个伪造平台返回 500
	badPlatform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badPlatform.Close()
	env2 := newE2EEnv(t, badPlatform.URL, svcToken)
	code, body = env2.callMachine(agentToken, "machine-001")
	if code != 503 || containsAll(body, "8 cores") {
		t.Fatalf("平台 500 应 503 且不泄露机器信息: %d %s", code, body)
	}

	// 健康检查匿名可用，但不暴露机器信息
	resp, err := http.Get(env.machine.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("健康检查应可用: %v", err)
	}
	hb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if containsAll(string(hb), "machine") {
		t.Fatalf("健康检查不应暴露机器信息")
	}

	_ = e
}

// 黑名单修改后“后续新发起的授权校验”立即返回新结果（已在上面的链路中覆盖，这里验证连续快速调用）
func TestE2EDenylistImmediateEffect(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	capability, svcToken := e.seedCapability(wangwu, "immediate-cap")
	_, zToken := e.seedCredential(zhangsan, "z-agent")
	env := newE2EEnv(t, e.ts.URL, svcToken)

	// 允许 → 拉黑 → 下一次调用立即拒绝（无缓存）
	if code, _ := env.callMachine(zToken, "machine-001"); code != 200 {
		t.Fatalf("初始应允许")
	}
	if err := e.st.AddDeny(e.ctx, capability.ID, zhangsan.ID); err != nil {
		t.Fatal(err)
	}
	if code, body := env.callMachine(zToken, "machine-001"); code != 403 || !containsAll(body, "user_blacklisted") {
		t.Fatalf("拉黑后立即拒绝: %d %s", code, body)
	}
	// 移出黑名单后立即恢复
	if err := e.st.RemoveDeny(e.ctx, capability.ID, zhangsan.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := env.callMachine(zToken, "machine-001"); code != 200 {
		t.Fatalf("移出黑名单后应恢复: %d", code)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}
