package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"agentpermit/internal/model"
)

func dashboardJSON(t *testing.T, c *httpClient, period string) model.DashboardSnapshot {
	t.Helper()
	resp, body := c.do(http.MethodGet, "/dashboard/stats?period="+period, nil, "")
	if resp.StatusCode != 200 {
		t.Fatalf("统计请求: %d %s", resp.StatusCode, body)
	}
	var data model.DashboardSnapshot
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDashboardAggregationIsolationAndPeriods(t *testing.T) {
	e := newTestEnv(t)
	owner := e.seedUser("dash_owner", "提供者")
	caller := e.seedUser("dash_caller", "调用者")
	unrelated := e.seedUser("dash_other", "无关账号")
	capA, _ := e.seedCapability(owner, "dash-visible")
	capB, _ := e.seedCapability(caller, "dash-caller-cap")
	hidden, _ := e.seedCapability(unrelated, "hidden-ranking")
	a, token := e.seedCredential(caller, "跨账号使用凭证")
	b, _ := e.seedCredential(owner, "我的凭证")
	now := time.Now().UTC().Add(-time.Minute)
	insert := func(event string, cap, subject, credential string, at time.Time) {
		t.Helper()
		outcome := "success"
		if event == "authorize_denied" {
			outcome = "failure"
		}
		if err := e.st.InsertAudit(e.ctx, &model.AuditLog{Event: event, CapabilityID: cap, SubjectUserID: subject, CredentialID: credential, Outcome: outcome, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 250; i++ {
		insert("authorize_allowed", capA.ID, caller.ID, a.ID, now)
	}
	for i := 0; i < 2; i++ {
		insert("authorize_allowed", capB.ID, owner.ID, b.ID, now)
	}
	insert("authorize_denied", capB.ID, owner.ID, b.ID, now)
	insert("floor_posted", "", owner.ID, b.ID, now)
	for i := 0; i < 100; i++ {
		insert("authorize_allowed", hidden.ID, unrelated.ID, "", now)
	}
	for i := 0; i < 5; i++ {
		insert("authorize_allowed", capA.ID, caller.ID, a.ID, now.Add(-48*time.Hour))
	}
	insert("authorize_allowed", capA.ID, caller.ID, a.ID, now.Add(-40*24*time.Hour))
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb(owner.Username, testPassword)
	data := dashboardJSON(t, c, "24h")
	if data.Scope != "我的数据" || data.Authorizations != 253 || data.Allowed != 252 || data.Denied != 1 || data.Posts != 1 || data.ActiveCredentials != 2 {
		t.Fatalf("账号统计不正确: %+v", data)
	}
	if len(data.CapabilityRanking) != 2 || data.CapabilityRanking[0].ID != capA.ID || data.CapabilityRanking[0].Count != 250 {
		t.Fatalf("完整统计不能截断到200条: %+v", data.CapabilityRanking)
	}
	var total int64
	for _, p := range data.Trend {
		total += p.Allowed + p.Denied
	}
	if total != data.Authorizations {
		t.Fatalf("趋势与总数不一致: %d", total)
	}
	if data.Resources.Capabilities != 1 || data.Resources.Credentials != 1 {
		t.Fatalf("资源按所有权统计: %+v", data.Resources)
	}
	_, body := c.do(http.MethodGet, "/dashboard/stats?period=24h&all=1", nil, "")
	for _, secret := range []string{hidden.Name, hidden.ID, unrelated.DisplayName, token, a.TokenHash, a.TokenHint} {
		if strings.Contains(body, secret) {
			t.Fatalf("统计泄露无关账号或秘密: %s", secret)
		}
	}
	week := dashboardJSON(t, c, "7d")
	month := dashboardJSON(t, c, "30d")
	if week.Authorizations != 258 || month.Authorizations != 258 || len(week.Trend) != 7 || len(month.Trend) != 15 {
		t.Fatal("时间范围未生效或包含窗口外数据")
	}
	if _, err := e.st.DB().Exec(`UPDATE users SET role='admin' WHERE id=?`, owner.ID); err != nil {
		t.Fatal(err)
	}
	global := dashboardJSON(t, c, "24h")
	if global.Scope != "全局数据" || global.Authorizations != 353 {
		t.Fatalf("管理员全局统计: %+v", global)
	}
}

func TestDashboardEmptyAuthenticationAndSafeMarkup(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("dash_empty", "空账号")
	c := newHTTPClient(t, e.ts.URL)
	for _, path := range []string{"/", "/dashboard/stats"} {
		if resp := c.get(path); resp.StatusCode != 302 || resp.Header.Get("Location") != "/login" {
			t.Fatal("统计需要网页会话")
		}
	}
	_, token := e.seedCredential(u, "</script><img src=x onerror=alert(1)>")
	if resp, _ := c.apiGet("/dashboard/stats", token); resp.StatusCode != 302 {
		t.Fatal("Agent Token 不能读网页统计接口")
	}
	c.loginViaWeb(u.Username, testPassword)
	data := dashboardJSON(t, c, "24h")
	if data.Authorizations != 0 || data.ApprovalRate != nil || data.Runtime.Requests != 0 {
		t.Fatal("没有请求时不能显示虚构比例或把面板轮询计数")
	}
	for _, path := range []string{"/?period=all", "/dashboard/stats?period=all"} {
		if resp := c.get(path); resp.StatusCode != 400 {
			t.Fatal("拒绝无效时间范围")
		}
	}
	// 使用真实 API 产生安全敏感名称，嵌入初始数据时必须保持 JSON 转义。
	getJSON(t, e.ts.URL, "/api/v1/agent/me", token)
	if err := e.st.InsertAudit(e.ctx, &model.AuditLog{Event: "floor_posted", ActorUserID: u.ID, CredentialID: dataID(t, e, u), Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	page := c.getBody("/")
	if !containsAll(page, "运行总览", "dashboard.css", "dashboard.js", "application/json", "能力热度榜") {
		t.Fatal("完整首页面板未渲染")
	}
	if strings.Contains(page, "</script><img src=x") || strings.Contains(page, token) {
		t.Fatal("初始数据不能造成脚本标签注入或泄露凭证")
	}
	match := strings.SplitN(page, `id="dashboard-data">`, 2)
	if len(match) != 2 {
		t.Fatal("初始数据缺失")
	}
	raw := strings.SplitN(match[1], "</script>", 2)[0]
	var decoded model.DashboardSnapshot
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("初始数据不是合法JSON: %v", err)
	}
}

func dataID(t *testing.T, e *testEnv, u *model.User) string {
	t.Helper()
	records, err := e.st.ListAgentCredentialsByOwner(e.ctx, u.ID)
	if err != nil || len(records) != 1 {
		t.Fatal("凭证 fixture 错误")
	}
	return records[0].ID
}

func TestDashboardLiveConcurrencyAndAccountScope(t *testing.T) {
	e := newTestEnv(t)
	a := e.seedUser("live_a", "A")
	b := e.seedUser("live_b", "B")
	_, tokenA := e.seedCredential(a, "A凭证")
	_, tokenB := e.seedCredential(b, "B凭证")
	entered := make(chan struct{}, 3)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	blocked := httptest.NewServer(e.srv.baseMiddleware(e.srv.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, c *model.AgentCredential, u *model.User) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(204)
	})))
	defer blocked.Close()
	completed := make(chan error, 3)
	for _, token := range []string{tokenA, tokenA, tokenB} {
		go func(token string) {
			req, _ := http.NewRequest("GET", blocked.URL+"/api/v1/blocked", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			completed <- err
		}(token)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			once.Do(func() { close(release) })
			t.Fatal("请求没有进入阻塞处理器")
		}
	}
	if v := e.srv.metrics.snapshot(a.ID, false); v.Current != 2 || v.Peak != 2 {
		t.Fatalf("真实请求并发未计数: %+v", v)
	}
	if v := e.srv.metrics.snapshot(b.ID, false); v.Current != 1 {
		t.Fatalf("账号范围互相污染: %+v", v)
	}
	if v := e.srv.metrics.snapshot("", true); v.Current != 3 {
		t.Fatal("管理员并发不正确")
	}
	once.Do(func() { close(release) })
	for i := 0; i < 3; i++ {
		if err := <-completed; err != nil {
			t.Fatal(err)
		}
	}
	if v := e.srv.metrics.snapshot(a.ID, false); v.Current != 0 || v.Requests != 2 || v.AverageMS == nil {
		t.Fatalf("请求完成后没有释放: %+v", v)
	}
	// 服务授权请求同时关联能力所有者与凭证所有者，重复身份不会重复计数。
	_, svc := e.seedCapability(a, "live-cap")
	e.authorize(svc, tokenB)
	if e.srv.metrics.snapshot(a.ID, false).Requests != 3 || e.srv.metrics.snapshot(b.ID, false).Requests != 2 {
		t.Fatal("服务授权未归属到提供者与使用者")
	}
}

func TestDashboardRuntimeWindowExpiresAndRecoversPanic(t *testing.T) {
	now := time.Unix(10000, 0)
	m := newRequestMetrics(func() time.Time { return now })
	o := m.begin()
	m.attribute(o, "a", "a")
	now = now.Add(20 * time.Millisecond)
	m.finish(o)
	if v := m.snapshot("a", false); v.Requests != 1 || v.Peak != 1 || v.AverageMS == nil || *v.AverageMS != 20 {
		t.Fatalf("重复归属或延时计算错误: %+v", v)
	}
	now = now.Add(301 * time.Second)
	if v := m.snapshot("a", false); v.Requests != 0 || v.Peak != 0 || v.AverageMS != nil {
		t.Fatal("过期窗口不能继续显示旧数据")
	}
	long := m.begin()
	m.attribute(long, "a")
	now = now.Add(301 * time.Second)
	m.finish(long)
	if v := m.snapshot("a", false); v.Current != 0 || v.Peak != 1 || v.Requests != 1 {
		t.Fatal("长请求完成前的窗口并发峰值必须保留")
	}
	e := newTestEnv(t)
	h := e.srv.baseMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("test") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/panic", nil))
	if rec.Code != 500 || e.srv.metrics.snapshot("", true).Current != 0 {
		t.Fatal("panic后请求并发没有释放")
	}
}
