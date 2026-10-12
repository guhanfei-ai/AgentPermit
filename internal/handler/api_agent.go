package handler

import (
	"net/http"
	"strings"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/policy"
	"agentpermit/internal/store"
)

// bearerToken 提取 Authorization: Bearer 头中的凭证。
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// requireAgentAPI 校验 Agent Token：无效、缺失、撤销、所属用户禁用一律 401。
// Agent Token 仅能访问 Agent API，不能用于网页登录或能力管理。
func (s *Server) requireAgentAPI(next func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "缺少 Bearer 凭证")
			return
		}
		credential, err := s.store.GetAgentCredentialByTokenHash(r.Context(), auth.HashToken(token))
		if err != nil {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "调用凭证无效")
			return
		}
		if !credential.IsActive() {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "调用凭证无效")
			return
		}
		owner, err := s.store.GetUserByID(r.Context(), credential.OwnerUserID)
		if err != nil || !owner.IsActive() {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "调用凭证无效")
			return
		}
		s.bindRuntime(r, owner.ID)
		next(w, r, credential, owner)
	}
}

// capabilityPublicJSON 是对调用者可见的能力字段（不含服务密钥与策略管理详情）。
// 内容取自 latest 标记指向的已发布快照：草稿编辑不影响 Agent 可见内容；
// version 供 Agent 在任务内固定使用同一版本。
type capabilityPublicJSON struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	EndpointURL    string    `json:"endpoint_url"`
	HTTPMethod     string    `json:"http_method"`
	APIPath        string    `json:"api_path"`
	HasHTTPBinding bool      `json:"has_http_binding"`
	Authentication *authInfo `json:"authentication"`
	SpecMarkdown   string    `json:"spec_markdown"`
	Version        int       `json:"version"`
}

type authInfo struct {
	Type       string `json:"type"`
	Credential string `json:"credential"`
}

// toPublicJSON 仅用发布快照组装内容；调用方保证 latest 非 nil。
func toPublicJSON(c *model.Capability, latest *model.CapabilityVersion) capabilityPublicJSON {
	out := capabilityPublicJSON{
		ID:             c.ID,
		Name:           latest.Name,
		Description:    latest.Description,
		EndpointURL:    latest.EndpointURL,
		HTTPMethod:     latest.HTTPMethod,
		APIPath:        latest.APIPath,
		HasHTTPBinding: latest.HasHTTPBinding(),
		SpecMarkdown:   latest.SpecMarkdown,
		Version:        latest.Version,
	}
	if out.HasHTTPBinding {
		out.Authentication = &authInfo{Type: "bearer", Credential: "caller_agent_token"}
	}
	return out
}

// evaluateForCredential 根据调用凭证的所属账号评估能力可访问性（集中走 policy 包）。
func (s *Server) evaluateForCredential(r *http.Request, credential *model.AgentCredential, owner *model.User, c *model.Capability) (policy.Decision, error) {
	ctx := r.Context()
	capOwner, err := s.store.GetUserByID(ctx, c.OwnerUserID)
	if err != nil {
		return policy.Decision{}, err
	}
	denied, err := s.store.IsDenied(ctx, c.ID, credential.OwnerUserID)
	if err != nil {
		return policy.Decision{}, err
	}
	allowlisted, err := s.store.IsAllowlisted(ctx, c.ID, credential.OwnerUserID)
	if err != nil {
		return policy.Decision{}, err
	}
	return policy.Evaluate(policy.Input{
		Credential:      credential,
		CredentialOwner: owner,
		Capability:      c,
		CapOwner:        capOwner,
		Denied:          denied,
		Allowlisted:     allowlisted,
	}), nil
}

// apiCredentialMe 返回当前凭证记录与所属账号，沿用原 API 字段，不含任何摘要、哈希等内部字段。
func (s *Server) apiCredentialMe(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User) {
		writeJSON(w, r, http.StatusOK, map[string]any{
			"agent_id":           credential.ID,
			"agent_name":         credential.Name,
			"owner_user_id":      owner.ID,
			"owner_username":     owner.Username,
			"owner_display_name": owner.DisplayName,
		})
	})(w, r)
}

// apiCapabilities 列出当前凭证所属账号有权访问的全部能力。
func (s *Server) apiCapabilities(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User) {
		caps, err := s.store.ListAllCapabilities(r.Context())
		if err != nil {
			s.logger.Error("查询能力失败", "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			return
		}
		out := []capabilityPublicJSON{}
		for _, c := range caps {
			dec, err := s.evaluateForCredential(r, credential, owner, c)
			if err != nil {
				s.logger.Error("策略评估失败", "err", err)
				continue
			}
			if dec.Allowed {
				latest, err := s.store.GetCapabilityLatestSnapshot(r.Context(), c.ID)
				if err != nil {
					s.logger.Error("查询发布版本失败", "err", err, "capability_id", c.ID)
					continue
				}
				out = append(out, toPublicJSON(c, latest))
			}
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"capabilities": out})
	})(w, r)
}

// apiCapabilityDetail 能力详情：不存在或无权访问统一 404。
func (s *Server) apiCapabilityDetail(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User) {
		id := r.PathValue("id")
		c, err := s.store.GetCapabilityByID(r.Context(), id)
		if err != nil {
			s.jsonError(w, r, http.StatusNotFound, "not_found", "能力不存在")
			return
		}
		dec, err := s.evaluateForCredential(r, credential, owner, c)
		if err != nil {
			s.logger.Error("策略评估失败", "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			return
		}
		if !dec.Allowed {
			s.jsonError(w, r, http.StatusNotFound, "not_found", "能力不存在")
			return
		}
		latest, err := s.store.GetCapabilityLatestSnapshot(r.Context(), c.ID)
		if err != nil {
			if err == store.ErrNotFound {
				s.jsonError(w, r, http.StatusNotFound, "not_found", "能力尚无可读取的发布版本")
			} else {
				s.logger.Error("查询发布版本失败", "err", err)
				s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			}
			return
		}
		writeJSON(w, r, http.StatusOK, toPublicJSON(c, latest))
	})(w, r)
}
