package handler

import (
	"net/http"
	"strings"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/policy"
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
func (s *Server) requireAgentAPI(next func(w http.ResponseWriter, r *http.Request, agent *model.Agent, owner *model.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "缺少 Bearer 凭证")
			return
		}
		agent, err := s.store.GetAgentByTokenHash(r.Context(), auth.HashToken(token))
		if err != nil {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "身份凭证无效")
			return
		}
		if !agent.IsActive() {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "身份凭证无效")
			return
		}
		owner, err := s.store.GetUserByID(r.Context(), agent.OwnerUserID)
		if err != nil || !owner.IsActive() {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "身份凭证无效")
			return
		}
		next(w, r, agent, owner)
	}
}

// capabilityPublicJSON 是对调用者可见的能力字段（不含服务密钥与策略管理详情）。
// 内容取自 latest 标记指向的已发布快照：草稿编辑不影响 Agent 可见内容；
// version 供 Agent 在任务内固定使用同一版本。
type capabilityPublicJSON struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	EndpointURL    string   `json:"endpoint_url"`
	HTTPMethod     string   `json:"http_method"`
	APIPath        string   `json:"api_path"`
	Authentication authInfo `json:"authentication"`
	SpecMarkdown   string   `json:"spec_markdown"`
	Version        int      `json:"version"`
}

type authInfo struct {
	Type       string `json:"type"`
	Credential string `json:"credential"`
}

// toPublicJSON 以 latest 发布快照组装对外字段；快照缺失时回退当前草稿字段（防御性兜底）。
func toPublicJSON(c *model.Capability, latest *model.CapabilityVersion) capabilityPublicJSON {
	out := capabilityPublicJSON{
		ID:             c.ID,
		Name:           c.Name,
		Description:    c.Description,
		EndpointURL:    c.EndpointURL,
		HTTPMethod:     c.HTTPMethod,
		APIPath:        c.APIPath,
		Authentication: authInfo{Type: "bearer", Credential: "caller_agent_token"},
		SpecMarkdown:   c.SpecMarkdown,
		Version:        c.LatestVersion,
	}
	if latest != nil {
		out.Name = latest.Name
		out.Description = latest.Description
		out.EndpointURL = latest.EndpointURL
		out.HTTPMethod = latest.HTTPMethod
		out.APIPath = latest.APIPath
		out.SpecMarkdown = latest.SpecMarkdown
		out.Version = latest.Version
	}
	return out
}

// evaluateForAgent 对 Agent 评估能力可访问性（集中走 policy 包）。
func (s *Server) evaluateForAgent(r *http.Request, agent *model.Agent, owner *model.User, c *model.Capability) (policy.Decision, error) {
	ctx := r.Context()
	capOwner, err := s.store.GetUserByID(ctx, c.OwnerUserID)
	if err != nil {
		return policy.Decision{}, err
	}
	denied, err := s.store.IsDenied(ctx, c.ID, agent.OwnerUserID)
	if err != nil {
		return policy.Decision{}, err
	}
	allowlisted, err := s.store.IsAllowlisted(ctx, c.ID, agent.OwnerUserID)
	if err != nil {
		return policy.Decision{}, err
	}
	return policy.Evaluate(policy.Input{
		Agent:       agent,
		AgentOwner:  owner,
		Capability:  c,
		CapOwner:    capOwner,
		Denied:      denied,
		Allowlisted: allowlisted,
	}), nil
}

// apiAgentMe 返回 Agent 自身身份，不含任何摘要、哈希等内部字段。
func (s *Server) apiAgentMe(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, agent *model.Agent, owner *model.User) {
		writeJSON(w, r, http.StatusOK, map[string]any{
			"agent_id":           agent.ID,
			"agent_name":         agent.Name,
			"owner_user_id":      owner.ID,
			"owner_username":     owner.Username,
			"owner_display_name": owner.DisplayName,
		})
	})(w, r)
}

// apiCapabilities 列出当前 Agent 所属用户有权访问的全部能力。
func (s *Server) apiCapabilities(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, agent *model.Agent, owner *model.User) {
		caps, err := s.store.ListAllCapabilities(r.Context())
		if err != nil {
			s.logger.Error("查询能力失败", "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			return
		}
		out := []capabilityPublicJSON{}
		for _, c := range caps {
			dec, err := s.evaluateForAgent(r, agent, owner, c)
			if err != nil {
				s.logger.Error("策略评估失败", "err", err)
				continue
			}
			if dec.Allowed {
				latest, err := s.store.GetCapabilityLatestSnapshot(r.Context(), c.ID)
				if err != nil {
					latest = nil // 快照缺失时回退草稿字段
				}
				out = append(out, toPublicJSON(c, latest))
			}
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"capabilities": out})
	})(w, r)
}

// apiCapabilityDetail 能力详情：不存在或无权访问统一 404。
func (s *Server) apiCapabilityDetail(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, agent *model.Agent, owner *model.User) {
		id := r.PathValue("id")
		c, err := s.store.GetCapabilityByID(r.Context(), id)
		if err != nil {
			s.jsonError(w, r, http.StatusNotFound, "not_found", "能力不存在")
			return
		}
		dec, err := s.evaluateForAgent(r, agent, owner, c)
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
			latest = nil
		}
		writeJSON(w, r, http.StatusOK, toPublicJSON(c, latest))
	})(w, r)
}
