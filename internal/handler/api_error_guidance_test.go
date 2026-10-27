package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

func assertAIStop(t *testing.T, status int, body, code, explanation string) {
	t.Helper()
	var response jsonErrorBody
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusForbidden || response.Error.Code != code || response.RequestID == "" {
		t.Fatalf("拒绝状态、原因或请求编号丢失：%d %s", status, body)
	}
	if response.Error.Retryable == nil || *response.Error.Retryable || !strings.Contains(response.Error.AIInstruction, explanation) || !strings.Contains(response.Error.AIInstruction, "不要自动重试") {
		t.Fatalf("缺少面向 AI 的停止说明：%s", body)
	}
}

func TestHolidayAIInstructionAcrossAgentAndServiceAPIs(t *testing.T) {
	e := newTrustEnv(t)
	_, temporary := e.grant(e.server, e.credential)
	p := &model.HolidayPlan{ID: store.NewID(), CreatedBy: e.admin.ID, Reason: "内部规则不应透传", TriggerAt: e.st.Now(), EndsAt: e.st.Now().Add(time.Minute)}
	if err := e.st.CreateHoliday(e.ctx, p); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(11)
	for _, endpoint := range []struct {
		method, path, token string
		body                any
	}{
		{"GET", "/agent/v1/me", e.agentToken, nil},
		{"GET", "/api/v1/agent/me", e.agentToken, nil},
		{"POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]string{"service_id": e.server.ID, "target_origin": e.server.Origin}},
		{"POST", "/agent/v1/threads/nonexistent/floors", e.agentToken, map[string]string{"body": "不得写入"}},
		{"POST", "/api/v1/service/temporary-credentials/introspect", e.serverToken, map[string]string{"temporary_credential": temporary}},
	} {
		t.Run(endpoint.path, func(t *testing.T) {
			status, body := e.jsonRequest(endpoint.method, endpoint.path, endpoint.token, endpoint.body)
			assertAIStop(t, status, body, "holiday_lockdown", "管理员已启用封网")
			if !strings.Contains(body, "禁止 AI 进行自动化作业") || !strings.Contains(body, "轮询") || strings.Contains(body, p.Reason) || strings.Contains(body, e.person.ID) || strings.Contains(body, temporary) {
				t.Fatalf("封网说明不完整或泄露内部信息：%s", body)
			}
		})
	}
	// 提示只描述当前拒绝，不改变原先到期自动解除的服务端规则。
	e.clock.Add(60)
	if status, body := e.jsonRequest("GET", "/agent/v1/me", e.agentToken, nil); status != 200 || strings.Contains(body, "ai_instruction") {
		t.Fatalf("封网结束后未恢复：%d %s", status, body)
	}
}

func TestWorkBanAIInstructions(t *testing.T) {
	for _, kind := range []string{"person", "credential", "condition"} {
		t.Run(kind, func(t *testing.T) {
			e := newTrustEnv(t)
			_, temporary := e.grant(e.server, e.credential)
			user, credential, server := "", "", ""
			code, explanation := "conditional_banned", "条件封禁"
			switch kind {
			case "person":
				user, code, explanation = e.person.ID, "person_banned", "当前账号"
			case "credential":
				credential, code, explanation = e.credential.ID, "credential_banned", "当前 AI 凭证"
			case "condition":
				server = e.server.ID
			}
			e.ban(kind, user, credential, server, "")
			status, body := e.jsonRequest("POST", "/api/v1/service/temporary-credentials/introspect", e.serverToken, map[string]string{"temporary_credential": temporary})
			assertAIStop(t, status, body, code, explanation)
			if kind == "condition" {
				status, body = e.jsonRequest("POST", "/agent/v1/temporary-credentials", e.agentToken, map[string]string{"service_id": e.server.ID, "target_origin": e.server.Origin})
				assertAIStop(t, status, body, "grant_denied", "不允许签发")
			} else {
				status, body = e.jsonRequest("GET", "/agent/v1/me", e.agentToken, nil)
				assertAIStop(t, status, body, code, explanation)
			}
		})
	}
}

func TestJSONErrorOptionalAndActionSpecificAIInstruction(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "/agent/v1/me", nil)
	r = r.WithContext(withRequestID(r.Context(), "request-example"))
	w := httptest.NewRecorder()
	s.jsonError(w, r, 422, "invalid_request", "参数有误")
	if w.Code != 422 || strings.Contains(w.Body.String(), "ai_instruction") || strings.Contains(w.Body.String(), "retryable") {
		t.Fatal("普通错误不应凭空增加重试策略", w.Body.String())
	}
	w = httptest.NewRecorder()
	retryable := false
	s.writeJSONError(w, r, 503, jsonErrorDetail{Code: "maintenance", Message: "维护中", AIInstruction: "管理员正在维护，请停止本次作业。", Retryable: &retryable})
	var response jsonErrorBody
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != 503 || response.Error.Code != "maintenance" || response.Error.AIInstruction != "管理员正在维护，请停止本次作业。" || response.Error.Retryable == nil || *response.Error.Retryable || response.RequestID != "request-example" {
		t.Fatal("具体动作的说明或原有错误字段丢失", w.Body.String())
	}
}
