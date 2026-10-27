package handler

import (
	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

func decodeTrustJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

// fieldGroupPayload 是发现、签发与核验响应中语义一致的编组描述：
// group_id 可直接用于签发申报，definition 使用签发时保存的快照，
// values 仅在签发/核验响应中出现。
func fieldGroupPayload(id, name string, definition json.RawMessage, values map[string]string) map[string]any {
	out := map[string]any{"group_id": id, "name": name, "definition": definition}
	if values != nil {
		out["values"] = values
	}
	return out
}

func (s *Server) apiTrustIntrospect(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		s.jsonError(w, r, 401, "unauthorized", "缺少服务校验凭证")
		return
	}
	if !s.limiter.AllowWindow("introspect:"+auth.HashToken(token), 600, time.Minute) {
		s.jsonError(w, r, 429, "rate_limited", "核验请求过于频繁")
		return
	}
	var body struct {
		TemporaryCredential string `json:"temporary_credential"`
	}
	if !decodeTrustJSON(w, r, &body) || len(body.TemporaryCredential) > 512 || body.TemporaryCredential == "" || strings.ContainsAny(body.TemporaryCredential, " \t\r\n,") {
		s.jsonError(w, r, 400, "invalid_request", "临时凭证格式错误")
		return
	}
	g, requesting, code, err := s.store.IntrospectGrant(r.Context(), auth.HashToken(token), auth.HashToken(body.TemporaryCredential))
	if err != nil {
		s.logger.Error("身份核验失败", "err", err)
		s.jsonError(w, r, 503, "unavailable", "暂时无法核验")
		return
	}
	if code != "" {
		status := 403
		if code == "unauthorized" {
			status = 401
		}
		event := &model.AuditLog{Event: "trust_verification_denied", Outcome: "failure", Reason: code}
		// 审计区分发起核验的Server与凭证绑定的Server；完全无法识别的凭证保持未知。
		if g != nil {
			detail := "server_id=" + requesting
			if g.ID != "" {
				detail += " grant_id=" + g.ID
				if g.ServerID != requesting {
					detail += " grant_server_id=" + g.ServerID
				}
			}
			event.SubjectUserID = g.UserID
			event.CredentialID = g.CredentialID
			event.Detail = detail
		} else if requesting != "" {
			event.Detail = "server_id=" + requesting
		}
		s.audit(r, event)
		s.jsonError(w, r, status, code, "本次请求未通过AgentPermit核验")
		return
	}
	s.audit(r, &model.AuditLog{Event: "trust_verified", SubjectUserID: g.UserID, CredentialID: g.CredentialID, Detail: "grant_id=" + g.ID + " server_id=" + g.ServerID})
	response := map[string]any{"active": true, "verification_id": requestIDFrom(r.Context()), "temporary_credential_id": g.ID, "service_id": g.ServerID, "subject": map[string]string{"user_id": g.UserID}, "expires_at": g.EffectiveExpiresAt()}
	// 编组与申报值来自签发时保存的快照，接入方不需要信任调用方自报字段。
	if g.GroupID != "" {
		response["field_group"] = fieldGroupPayload(g.GroupID, g.GroupName, json.RawMessage(g.GroupSnapshot), store.FormatFieldGroupValues(g.GroupValues))
	}
	writeJSON(w, r, 200, response)
}

func (s *Server) apiTrustedServers(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, a *model.AgentCredential, u *model.User) {
		items, err := s.store.ListTrustedServers(r.Context())
		if err != nil {
			s.jsonError(w, r, 503, "unavailable", "服务列表不可用")
			return
		}
		out := []map[string]any{}
		for _, v := range items {
			entry := map[string]any{"service_id": v.ID, "name": v.Name, "environment": v.Environment, "target_origin": v.Origin, "status": v.Status, "delivery": map[string]string{"type": "header", "name": temporaryHeader}}
			groups, err := s.store.ListFieldGroups(r.Context(), v.ID)
			if err != nil {
				s.jsonError(w, r, 503, "unavailable", "服务列表不可用")
				return
			}
			declared := []map[string]any{}
			for _, f := range groups {
				declared = append(declared, fieldGroupPayload(f.ID, f.Name, json.RawMessage(f.Definition), nil))
			}
			entry["field_groups"] = declared
			out = append(out, entry)
		}
		writeJSON(w, r, 200, map[string]any{"servers": out})
	})(w, r)
}

func (s *Server) apiGrantCreate(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, a *model.AgentCredential, u *model.User) {
		var body struct {
			ServerID     string          `json:"service_id"`
			Origin       string          `json:"target_origin"`
			ExpiresIn    int             `json:"expires_in"`
			FieldGroupID string          `json:"field_group_id"`
			FieldValues  json.RawMessage `json:"field_values"`
		}
		if !decodeTrustJSON(w, r, &body) {
			s.jsonError(w, r, 400, "invalid_request", "请求结构错误")
			return
		}
		// 固定300秒：expires_in 仅作兼容保留，合法值只有省略、0或300。
		if body.ExpiresIn != 0 && body.ExpiresIn != int(model.TemporaryGrantTTL/time.Second) {
			s.jsonError(w, r, 422, "invalid_expiry", "临时凭证有效期固定为300秒，不支持自选时长")
			return
		}
		v, err := s.store.GetTrustedServer(r.Context(), body.ServerID)
		if err != nil {
			s.jsonError(w, r, 404, "not_found", "Server不存在")
			return
		}
		if body.Origin != v.Origin {
			s.jsonError(w, r, 403, "grant_scope_mismatch", "目标地址与登记不符")
			return
		}
		// 申报值原样透传给存储层校验：省略（nil）与空对象 "{}" 语义不同，
		// null／数字等非法类型不在入口被洗成字符串。
		values := ""
		if len(body.FieldValues) > 0 {
			if len(body.FieldValues) > 8192 {
				s.jsonError(w, r, 422, "invalid_field_values", "申报值过大")
				return
			}
			values = string(body.FieldValues)
		}
		if body.FieldGroupID != "" && values == "" {
			s.jsonError(w, r, 422, "invalid_field_values", "选择编组时必须提交field_values（全部可选时可为空对象{}）")
			return
		}
		token, hash, hint := auth.NewToken(temporaryTokenPrefix)
		g := &model.TemporaryGrant{ID: store.NewID(), UserID: u.ID, CredentialID: a.ID, ServerID: v.ID, TargetOrigin: body.Origin, IssuedBy: u.ID, TokenHash: hash, TokenHint: hint, ParentTokenHash: a.TokenHash, GroupID: body.FieldGroupID, GroupValues: values}
		if err := s.store.IssueTemporaryGrant(r.Context(), g); err != nil {
			switch err {
			case store.ErrInvalidFieldGroup:
				s.jsonError(w, r, 422, "invalid_field_group", "编组不存在或不属于该Server")
			case store.ErrInvalidFieldValues:
				s.jsonError(w, r, 422, "invalid_field_values", "申报值不符合编组定义")
			case store.ErrInvalidTrust:
				s.jsonError(w, r, 403, "grant_denied", "当前状态不允许签发")
			default:
				s.jsonError(w, r, 503, "unavailable", "暂时无法签发")
			}
			return
		}
		s.audit(r, &model.AuditLog{Event: "temporary_grant_issued", ActorUserID: u.ID, SubjectUserID: u.ID, CredentialID: a.ID, Detail: "grant_id=" + g.ID + " server_id=" + g.ServerID + " via=agent_api"})
		response := map[string]any{"temporary_credential_id": g.ID, "temporary_credential": token, "service_id": g.ServerID, "target_origin": g.TargetOrigin, "expires_in": int(model.TemporaryGrantTTL / time.Second), "expires_at": g.ExpiresAt, "delivery": map[string]string{"type": "header", "name": temporaryHeader}}
		if g.GroupID != "" {
			response["field_group"] = fieldGroupPayload(g.GroupID, g.GroupName, json.RawMessage(g.GroupSnapshot), store.FormatFieldGroupValues(g.GroupValues))
		}
		writeJSON(w, r, 201, response)
	})(w, r)
}
