package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// postJSON 以 Bearer 凭证提交 JSON，返回状态码与响应体。
func postJSON(t *testing.T, base, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer resp.Body.Close()
	b := new(bytes.Buffer)
	b.ReadFrom(resp.Body)
	out := map[string]any{}
	if b.Len() > 0 {
		json.Unmarshal(b.Bytes(), &out)
	}
	return resp.StatusCode, out
}

// getJSON 以 Bearer 凭证读取 JSON API。
func getJSON(t *testing.T, base, path, bearer string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求 %s 失败: %v", path, err)
	}
	defer resp.Body.Close()
	b := new(bytes.Buffer)
	b.ReadFrom(resp.Body)
	out := map[string]any{}
	if b.Len() > 0 {
		json.Unmarshal(b.Bytes(), &out)
	}
	return resp.StatusCode, out
}

// seedProjectViaWeb 用网页流程创建频道（真人操作）。
func seedProjectViaWeb(t *testing.T, e *testEnv, owner *model.User, slug string) *model.Project {
	t.Helper()
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb(owner.Username, testPassword)
	c.refreshCSRF("/square")
	resp, _ := c.postForm("/projects", url.Values{
		"name": {"频道-" + slug}, "slug": {slug}, "description": {"协作空间测试"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("创建频道失败: %d", resp.StatusCode)
	}
	p, err := e.st.GetProjectBySlug(e.ctx, slug)
	if err != nil {
		t.Fatalf("查询频道失败: %v", err)
	}
	return p
}

// seedThreadViaWeb 用网页流程创建留言板（仅真人可创建）。
func seedThreadViaWeb(t *testing.T, e *testEnv, owner *model.User, p *model.Project, title string) *model.Thread {
	t.Helper()
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb(owner.Username, testPassword)
	c.refreshCSRF("/projects/" + p.Slug)
	resp, _ := c.postForm("/projects/"+p.Slug+"/threads", url.Values{
		"title": {title}, "body": {title + "：首帖内容"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("创建留言板失败: %d", resp.StatusCode)
	}
	threads, err := e.st.ListThreadsByProject(e.ctx, p.ID)
	if err != nil || len(threads) != 1 {
		t.Fatalf("查询留言板失败: %v len=%d", err, len(threads))
	}
	return threads[0]
}

// TestCollabLoop 验证交接文档建议的协作闭环：
// 真人创建频道与线程 → 不同真人名下的两个 Agent 追加消息 →
// 新会话的 Agent 按楼层增量接手 → 管理员禁止某真人后其全部 Agent 无法发言 →
// 精准禁单个 Agent 只影响该 Agent → 真人网页追加与关闭/重开。
func TestCollabLoop(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")     // 频道管理员
	zhangsan := e.seedUser("zhangsan", "张三") // 协作者
	lisi := e.seedUser("lisi", "李四")         // 协作者

	p := seedProjectViaWeb(t, e, wangwu, "sre-collab")
	thread := seedThreadViaWeb(t, e, wangwu, p, "值班交接")

	zAgent1, zToken1 := e.seedCredential(zhangsan, "张三-Agent-1")
	_, zToken2 := e.seedCredential(zhangsan, "张三-Agent-2")
	_, lToken := e.seedCredential(lisi, "李四-Agent")

	// 1) 不同真人的两个 Agent 追加楼层
	code, body := postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", zToken1, `{"body":"张三 Agent-1：已接手，正在排查 disk-full 告警"}`)
	if code != http.StatusCreated {
		t.Fatalf("张三 Agent-1 追加应 201: %d %v", code, body)
	}
	code, body = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", lToken, `{"body":"李四 Agent：根因是日志未轮转，建议先truncate"}`)
	if code != http.StatusCreated {
		t.Fatalf("李四 Agent 追加应 201: %d %v", code, body)
	}

	// 2) 新会话的 Agent 按楼层增量接手：after=2 只返回第 3 楼起
	code, body = getJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"?after=2", zToken2)
	if code != http.StatusOK {
		t.Fatalf("增量读取应 200: %d", code)
	}
	floors := body["floors"].([]any)
	if len(floors) != 1 || floors[0].(map[string]any)["floor_no"].(float64) != 3 {
		t.Fatalf("after=2 应只返回第 3 楼: %v", floors)
	}
	if floors[0].(map[string]any)["agent_name"] != "李四-Agent" {
		t.Fatalf("楼层应带 Agent 名: %v", floors[0])
	}
	if body["next_after"].(float64) != 3 || body["has_more"] != false {
		t.Fatalf("next_after/has_more 应为 3/false: %v", body)
	}

	// 3) Agent 不能创建留言板：无 API 路由（405），网页路由对 Bearer 不构成登录态（302 跳登录）
	code, _ = postJSON(t, e.ts.URL, "/api/v1/projects", zToken1, `{"name":"x"}`)
	if code != http.StatusMethodNotAllowed {
		t.Fatalf("Agent 创建频道应 405: %d", code)
	}
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/projects/"+p.Slug+"/threads", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+zToken1)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	// Agent 无会话 Cookie 与 CSRF Token，网页表单先被 CSRF 拦截（403）；无论哪层都轮不到创建
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusFound {
		t.Fatalf("Agent 走网页创建留言板应被拒绝: %d", resp.StatusCode)
	}

	// 4) 管理员 user 级禁言张三 → 其全部 Agent 403，本人网页追加也被拒
	admin := newHTTPClient(t, e.ts.URL)
	admin.loginViaWeb(wangwu.Username, testPassword)
	admin.refreshCSRF("/projects/" + p.Slug + "/admin")
	resp, _ = admin.postForm("/projects/"+p.Slug+"/bans/add", url.Values{
		"username": {zhangsan.Username}, "reason": {"测试禁言"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("添加禁言失败: %d", resp.StatusCode)
	}
	code, body = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", zToken1, `{"body":"should fail"}`)
	if code != http.StatusForbidden || body["error"].(map[string]any)["code"] != "banned" {
		t.Fatalf("禁言后张三 Agent-1 应 403 banned: %d %v", code, body)
	}
	code, _ = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", zToken2, `{"body":"should fail"}`)
	if code != http.StatusForbidden {
		t.Fatalf("禁言后张三 Agent-2 应 403: %d", code)
	}
	// 禁言不影响读取（可读不可写）
	code, body = getJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID, zToken1)
	if code != http.StatusOK {
		t.Fatalf("禁言后读取应 200: %d", code)
	}
	// 张三本人网页追加也被拒（留言板页因禁言无表单，CSRF 从频道页取）
	zc := newHTTPClient(t, e.ts.URL)
	zc.loginViaWeb(zhangsan.Username, testPassword)
	zc.refreshCSRF("/projects/" + p.Slug)
	resp, _ = zc.postForm("/threads/"+thread.ID+"/floors", url.Values{"body": {"真人也应被禁言拦截"}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("user 级禁言应拦截本人网页追加: %d", resp.StatusCode)
	}
	if page := zc.getBody("/threads/" + thread.ID); !strings.Contains(page, "已被频道禁言") {
		t.Fatalf("网页应提示被禁言")
	}
	// 李四不受影响
	code, _ = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", lToken, `{"body":"李四 Agent：不受影响"}`)
	if code != http.StatusCreated {
		t.Fatalf("李四应正常发言: %d", code)
	}

	// 5) 解除禁言后恢复
	resp, _ = admin.postForm("/projects/"+p.Slug+"/bans/remove", url.Values{
		"user_id": {zhangsan.ID}, "agent_id": {""},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("解除禁言失败: %d", resp.StatusCode)
	}
	code, _ = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", zToken1, `{"body":"张三 Agent-1：禁言已解除，恢复发言"}`)
	if code != http.StatusCreated {
		t.Fatalf("解除禁言后张三 Agent-1 应恢复发言: %d", code)
	}

	// 6) 精准禁单个 Agent：只影响 zAgent1
	admin.refreshCSRF("/projects/" + p.Slug + "/admin")
	resp, _ = admin.postForm("/projects/"+p.Slug+"/bans/add", url.Values{
		"username": {zhangsan.Username}, "agent_id": {zAgent1.ID}, "reason": {"精准禁言"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("精准禁言失败: %d", resp.StatusCode)
	}
	code, _ = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", zToken1, `{"body":"x"}`)
	if code != http.StatusForbidden {
		t.Fatalf("被精准禁言的 Agent-1 应 403: %d", code)
	}
	code, _ = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", zToken2, `{"body":"张三 Agent-2：未受影响"}`)
	if code != http.StatusCreated {
		t.Fatalf("同主人的 Agent-2 应正常发言: %d", code)
	}

	// 7) 真人（王五）网页追加楼层
	admin.refreshCSRF("/threads/" + thread.ID)
	resp, _ = admin.postForm("/threads/"+thread.ID+"/floors", url.Values{"body": {"王五：问题已解决，感谢两位"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("真人追加楼层应成功: %d", resp.StatusCode)
	}
	th, _ := e.st.GetThreadByID(e.ctx, thread.ID)
	// 首帖1 + 张三A1(2) + 李四(3,4) + 张三A1恢复(5) + 张三A2(6) + 王五(7)
	if th.FloorCount != 7 {
		t.Fatalf("楼层计数应为 7: %d", th.FloorCount)
	}

	// 8) 关闭留言板：所有人不可追加；重开后恢复
	admin.refreshCSRF("/threads/" + thread.ID)
	resp, _ = admin.postForm("/threads/"+thread.ID+"/close", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("关闭留言板失败: %d", resp.StatusCode)
	}
	code, body = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", lToken, `{"body":"closed"}`)
	if code != http.StatusConflict || body["error"].(map[string]any)["code"] != "thread_closed" {
		t.Fatalf("关闭后追加应 409 thread_closed: %d %v", code, body)
	}
	admin.refreshCSRF("/threads/" + thread.ID)
	resp, _ = admin.postForm("/threads/"+thread.ID+"/reopen", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("重开留言板失败: %d", resp.StatusCode)
	}
	code, _ = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", lToken, `{"body":"reopened"}`)
	if code != http.StatusCreated {
		t.Fatalf("重开后追加应 201: %d", code)
	}

	// 9) 非频道管理员不能访问管理页
	zc2 := newHTTPClient(t, e.ts.URL)
	zc2.loginViaWeb(zhangsan.Username, testPassword)
	resp = zc2.get("/projects/" + p.Slug + "/admin")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("非频道管理员访问管理页应 403: %d", resp.StatusCode)
	}
}

// TestThreadAPIGuards 留言板追加的守卫：401/400/404/409。
func TestThreadAPIGuards(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	p := seedProjectViaWeb(t, e, wangwu, "guards")
	thread := seedThreadViaWeb(t, e, wangwu, p, "守卫测试")
	_, token := e.seedCredential(zhangsan, "z-agent")

	// 无凭证 401
	code, _ := postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", "", `{"body":"x"}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("无凭证应 401: %d", code)
	}
	// 空 body 400
	code, body := postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", token, `{"body":"  "}`)
	if code != http.StatusBadRequest || body["error"].(map[string]any)["code"] != "invalid_request" {
		t.Fatalf("空 body 应 400: %d %v", code, body)
	}
	// 不存在的留言板 404
	code, _ = postJSON(t, e.ts.URL, "/api/v1/threads/nonexistent/floors", token, `{"body":"x"}`)
	if code != http.StatusNotFound {
		t.Fatalf("不存在留言板应 404: %d", code)
	}
	// 归档频道 → 409 project_archived
	if err := e.st.SetProjectStatus(e.ctx, p.ID, model.ProjectStatusArchived); err != nil {
		t.Fatal(err)
	}
	code, body = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", token, `{"body":"x"}`)
	if code != http.StatusConflict || body["error"].(map[string]any)["code"] != "project_archived" {
		t.Fatalf("归档频道追加应 409 project_archived: %d %v", code, body)
	}
	// 归档频道不能新建留言板
	admin := newHTTPClient(t, e.ts.URL)
	admin.loginViaWeb(wangwu.Username, testPassword)
	admin.refreshCSRF("/projects/" + p.Slug)
	resp, _ := admin.postForm("/projects/"+p.Slug+"/threads", url.Values{"title": {"t2"}, "body": {"b"}})
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("归档频道新建留言板应被拒: %d", resp.StatusCode)
	}
	if page := admin.getBody("/projects/" + p.Slug); !strings.Contains(page, "已归档") {
		t.Fatalf("频道页应提示已归档")
	}
}

// TestThreadFloorCap 验证 5000 楼上限（含首帖）：最后一位成功、越界 409 thread_full。
func TestThreadFloorCap(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	p := seedProjectViaWeb(t, e, wangwu, "cap-test")
	thread := seedThreadViaWeb(t, e, wangwu, p, "上限测试")
	_, token := e.seedCredential(zhangsan, "z-agent")

	// 直接灌楼层到 4999（含首帖），绕开逐层 API 调用提速
	ts := time.Now().UTC().Format(model.TimeLayout)
	var b strings.Builder
	b.WriteString(`INSERT INTO floors (id, thread_id, floor_no, author_user_id, agent_id, body, created_at) VALUES `)
	args := make([]any, 0, 4998*4)
	for i := 2; i <= 4999; i++ {
		if i > 2 {
			b.WriteString(",")
		}
		b.WriteString("(?,?,?,?,'',?,?)")
		args = append(args, store.NewID(), thread.ID, i, wangwu.ID, fmt.Sprintf("灌水楼层 %d", i), ts)
	}
	if _, err := e.st.DB().ExecContext(e.ctx, b.String(), args...); err != nil {
		t.Fatalf("灌楼层失败: %v", err)
	}
	if _, err := e.st.DB().ExecContext(e.ctx, `UPDATE threads SET floor_count=4999 WHERE id=?`, thread.ID); err != nil {
		t.Fatal(err)
	}

	// 第 5000 楼成功
	code, body := postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", token, `{"body":"第 5000 楼"}`)
	if code != http.StatusCreated || body["floor"].(map[string]any)["floor_no"].(float64) != 5000 {
		t.Fatalf("第 5000 楼应成功: %d %v", code, body)
	}
	// 第 5001 楼被拒
	code, body = postJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"/floors", token, `{"body":"should fail"}`)
	if code != http.StatusConflict || body["error"].(map[string]any)["code"] != "thread_full" {
		t.Fatalf("超过上限应 409 thread_full: %d %v", code, body)
	}
	// 满员后仍可读取，且旧记录未被覆盖
	code, body = getJSON(t, e.ts.URL, "/api/v1/threads/"+thread.ID+"?after=4998", token)
	if code != http.StatusOK {
		t.Fatalf("满员后读取应 200: %d", code)
	}
	floors := body["floors"].([]any)
	if len(floors) != 2 {
		t.Fatalf("after=4998 应有 2 楼: %d", len(floors))
	}
}

// TestAgentsmdVersioning AGENTS.md：草稿不外泄、发布、latest 回滚、权限。
func TestAgentsmdVersioning(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	p := seedProjectViaWeb(t, e, wangwu, "agentsmd-test")
	_, token := e.seedCredential(zhangsan, "z-agent")

	// 未发布时 Agent 读到 version 0
	code, body := getJSON(t, e.ts.URL, "/api/v1/projects/"+p.ID, token)
	if code != http.StatusOK || body["agents_md"].(map[string]any)["version"].(float64) != 0 {
		t.Fatalf("未发布 AGENTS.md 应 version 0: %d %v", code, body)
	}

	admin := newHTTPClient(t, e.ts.URL)
	admin.loginViaWeb(wangwu.Username, testPassword)
	saveDraft := func(text string) {
		t.Helper()
		admin.refreshCSRF("/projects/" + p.Slug + "/agents-md")
		resp, _ := admin.postForm("/projects/"+p.Slug+"/agents-md/draft", url.Values{"body": {text}})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("保存草稿失败: %d", resp.StatusCode)
		}
	}
	publish := func() {
		t.Helper()
		admin.refreshCSRF("/projects/" + p.Slug + "/agents-md")
		resp, _ := admin.postForm("/projects/"+p.Slug+"/agents-md/publish", url.Values{})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("发布失败: %d", resp.StatusCode)
		}
	}
	setLatest := func(version string) {
		t.Helper()
		admin.refreshCSRF("/projects/" + p.Slug + "/agents-md")
		resp, _ := admin.postForm("/projects/"+p.Slug+"/agents-md/latest", url.Values{"version": {version}})
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("设 latest 失败: %d", resp.StatusCode)
		}
	}

	// v1 发布
	saveDraft("# 引导 v1\n值班先看告警面板")
	publish()
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects/"+p.ID, token)
	doc := body["agents_md"].(map[string]any)
	if doc["version"].(float64) != 1 || !strings.Contains(doc["body"].(string), "值班先看告警面板") {
		t.Fatalf("Agent 应读到 v1: %v", doc)
	}

	// 草稿更新不外泄
	saveDraft("# 引导 v2（草稿）\n新流程待发布")
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects/"+p.ID, token)
	doc = body["agents_md"].(map[string]any)
	if doc["version"].(float64) != 1 || strings.Contains(doc["body"].(string), "草稿") {
		t.Fatalf("草稿不应外泄: %v", doc)
	}

	// 发布 v2 → Agent 看到 v2
	publish()
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects/"+p.ID, token)
	doc = body["agents_md"].(map[string]any)
	if doc["version"].(float64) != 2 || !strings.Contains(doc["body"].(string), "新流程") {
		t.Fatalf("Agent 应读到 v2: %v", doc)
	}

	// latest 回指 v1（回滚）
	setLatest("1")
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects/"+p.ID, token)
	doc = body["agents_md"].(map[string]any)
	if doc["version"].(float64) != 1 || !strings.Contains(doc["body"].(string), "值班先看告警面板") {
		t.Fatalf("回滚后 Agent 应读到 v1: %v", doc)
	}

	// 非频道管理员不能进编辑页
	zc := newHTTPClient(t, e.ts.URL)
	zc.loginViaWeb(zhangsan.Username, testPassword)
	resp := zc.get("/projects/" + p.Slug + "/agents-md")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("非管理员访问 AGENTS.md 编辑页应 403: %d", resp.StatusCode)
	}

	// 频道列表与线程列表 API 可用
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects", token)
	if code != http.StatusOK || len(body["projects"].([]any)) != 1 {
		t.Fatalf("频道列表应含 1 项: %d %v", code, body)
	}
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects/"+p.ID+"/threads", token)
	if code != http.StatusOK || len(body["threads"].([]any)) != 0 {
		t.Fatalf("线程列表应为空: %d %v", code, body)
	}
	// slug 也能定位频道
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects/"+p.Slug, token)
	if code != http.StatusOK {
		t.Fatalf("按 slug 读频道应 200: %d", code)
	}
}

// TestCapabilityVersions 能力内容版本：创建即 v1、草稿不外泄、发布 v2、latest 回滚、
// 访问控制与内容版本分离（回滚不恢复被撤销的访问权）。
func TestCapabilityVersions(t *testing.T) {
	e := newTestEnv(t)
	wangwu := e.seedUser("wangwu", "王五")
	zhangsan := e.seedUser("zhangsan", "张三")
	capability, _ := e.seedCapability(wangwu, "versioned-cap")
	_, token := e.seedCredential(zhangsan, "z-agent")

	// 创建即 v1
	code, body := getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capability.ID, token)
	if code != http.StatusOK || body["version"].(float64) != 1 {
		t.Fatalf("新能力应自动发布 v1: %d %v", code, body)
	}

	// 编辑草稿：不发布不生效
	capability.Name = "新版名称"
	capability.SpecMarkdown = "v2 内容草稿"
	if err := e.st.UpdateCapability(e.ctx, capability.ID, wangwu.ID, capability); err != nil {
		t.Fatal(err)
	}
	code, body = getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capability.ID, token)
	if body["version"].(float64) != 1 || body["name"] != "查询机器配置-versioned-cap" {
		t.Fatalf("草稿不应外泄: %v", body)
	}

	// 发布 v2 → 生效
	if _, err := e.st.PublishCapability(e.ctx, capability.ID); err != nil {
		t.Fatal(err)
	}
	code, body = getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capability.ID, token)
	if body["version"].(float64) != 2 || body["name"] != "新版名称" {
		t.Fatalf("发布后应读到 v2: %v", body)
	}

	// latest 回指 v1（内容回滚），但访问控制不回滚：拉黑张三后依旧拒绝
	if err := e.st.SetCapabilityLatest(e.ctx, capability.ID, 1); err != nil {
		t.Fatal(err)
	}
	code, body = getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capability.ID, token)
	if body["version"].(float64) != 1 || body["name"] != "查询机器配置-versioned-cap" {
		t.Fatalf("回滚后应读到 v1: %v", body)
	}
	if err := e.st.AddDeny(e.ctx, capability.ID, zhangsan.ID); err != nil {
		t.Fatal(err)
	}
	code, _ = getJSON(t, e.ts.URL, "/api/v1/capabilities/"+capability.ID, token)
	if code != http.StatusNotFound {
		t.Fatalf("内容回滚不应恢复访问权（黑名单仍生效）: %d", code)
	}

	// 网页版本管理页（所有者可见）
	c := newHTTPClient(t, e.ts.URL)
	c.loginViaWeb(wangwu.Username, testPassword)
	resp := c.get("/capabilities/" + capability.ID + "/versions")
	page := c.getBody("/capabilities/" + capability.ID + "/versions")
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "v2") || !strings.Contains(page, "latest") {
		t.Fatalf("版本管理页应展示版本历史: %d", resp.StatusCode)
	}
}
