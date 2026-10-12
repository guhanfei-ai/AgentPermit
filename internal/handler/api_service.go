package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/policy"
)

const authorizeBodyLimit = 8 * 1024 // 授权请求体很小，额外收紧

type authorizeRequest struct {
	AgentToken   string `json:"agent_token"`
	CapabilityID string `json:"capability_id"` // 可选；若提供必须与 Service Token 绑定的能力一致
}

type authorizeCredentialInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type authorizeUserInfo struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

type authorizeResponse struct {
	Allowed      bool                     `json:"allowed"`
	Reason       string                   `json:"reason"`
	CapabilityID string                   `json:"capability_id"`
	Credential   *authorizeCredentialInfo `json:"agent,omitempty"`
	User         *authorizeUserInfo       `json:"user,omitempty"`
}

// apiServiceAuthorize 是独立服务使用的授权校验接口。
//
// 认证：能力自己的 Service Verification Token（Bearer）。
// 语义：Service Token 无效 → 401；Token 有效则完成授权判定并返回 200 决策对象
// （allowed=false 表示拒绝，不是 HTTP 错误）。平台内部故障 → 500，调用方应拒绝访问。
func (s *Server) apiServiceAuthorize(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "缺少 Service Token")
		return
	}
	tokenHash := auth.HashToken(token)
	// 限流以 Service Token 摘要为 key（单进程内存实现，不适用于多实例）。
	// 授权是服务间调用，阈值高于登录/注册。
	if !s.limiter.AllowWindow("authorize:"+tokenHash[:16], 120, time.Minute) {
		s.jsonError(w, r, http.StatusTooManyRequests, "rate_limited", "请求过于频繁")
		return
	}

	// 能力 ID 由已验证的 Service Token 绑定关系确定，不信任调用者指定
	cred, err := s.store.GetServiceCredentialByTokenHash(r.Context(), tokenHash)
	if err != nil {
		s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "Service Token 无效")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, authorizeBodyLimit))
	if err != nil {
		s.jsonError(w, r, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	var req authorizeRequest
	if err := json.Unmarshal(body, &req); err != nil || req.AgentToken == "" {
		s.jsonError(w, r, http.StatusBadRequest, "invalid_request", "请求体必须是包含 agent_token 的 JSON")
		return
	}
	if req.CapabilityID != "" && req.CapabilityID != cred.CapabilityID {
		s.jsonError(w, r, http.StatusBadRequest, "invalid_request", "capability_id 与 Service Token 绑定的能力不一致")
		return
	}

	credential, err := s.store.GetAgentCredentialByTokenHash(r.Context(), auth.HashToken(req.AgentToken))
	if err != nil {
		// 无效 Agent Token：不返回任何推测的用户身份
		s.writeAuthorizeDecision(w, r, cred.CapabilityID, policy.Decision{Allowed: false, Reason: policy.ReasonInvalidAgentToken}, nil, nil)
		return
	}
	owner, err := s.store.GetUserByID(r.Context(), credential.OwnerUserID)
	if err != nil {
		s.writeAuthorizeDecision(w, r, cred.CapabilityID, policy.Decision{Allowed: false, Reason: policy.ReasonInvalidAgentToken}, nil, nil)
		return
	}
	capability, err := s.store.GetCapabilityByID(r.Context(), cred.CapabilityID)
	if err != nil {
		// 数据不一致属于平台内部故障：500，调用方 fail closed
		s.logger.Error("授权时查询能力失败", "err", err, "capability_id", cred.CapabilityID)
		s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
		return
	}

	dec, err := s.evaluateForCredential(r, credential, owner, capability)
	if err != nil {
		s.logger.Error("授权评估失败", "err", err)
		s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
		return
	}
	if dec.Allowed {
		latest, err := s.store.GetCapabilityLatestSnapshot(r.Context(), capability.ID)
		if err != nil {
			s.logger.Error("授权时查询发布版本失败", "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			return
		}
		dec = policy.EvaluateHTTPService(dec, latest)
	}
	s.writeAuthorizeDecision(w, r, cred.CapabilityID, dec, credential, owner)
}

// writeAuthorizeDecision 输出决策并写审计。响应不包含任何 Token 原文或摘要。
func (s *Server) writeAuthorizeDecision(w http.ResponseWriter, r *http.Request, capabilityID string, dec policy.Decision, credential *model.AgentCredential, owner *model.User) {
	event := "authorize_denied"
	outcome := "failure"
	if dec.Allowed {
		event = "authorize_allowed"
		outcome = "success"
	}
	entry := &model.AuditLog{
		Event:        event,
		CapabilityID: capabilityID,
		Outcome:      outcome,
		Reason:       dec.Reason,
	}
	if credential != nil {
		entry.CredentialID = credential.ID
	}
	if owner != nil {
		entry.SubjectUserID = owner.ID
	}
	s.audit(r, entry)

	resp := authorizeResponse{
		Allowed:      dec.Allowed,
		Reason:       dec.Reason,
		CapabilityID: capabilityID,
	}
	// 仅在允许时返回调用者身份信息；拒绝时只返回必要信息
	if dec.Allowed && credential != nil && owner != nil {
		resp.Credential = &authorizeCredentialInfo{ID: credential.ID, Name: credential.Name}
		resp.User = &authorizeUserInfo{ID: owner.ID, Username: owner.Username, DisplayName: owner.DisplayName}
	}
	writeJSON(w, r, http.StatusOK, resp)
}
