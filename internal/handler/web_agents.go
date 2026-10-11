package handler

import (
	"net/http"
	"strings"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

func (s *Server) pageDashboard(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, http.StatusOK, "dashboard", "控制台", "dashboard", nil)
}

func (s *Server) pageAgents(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	agents, err := s.store.ListAgentsByOwner(r.Context(), u.ID)
	if err != nil {
		s.logger.Error("查询 Agent 失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "agents", "我的 Agent", "agents", map[string]any{"Agents": agents})
}

func (s *Server) pageAgentCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if name == "" || len(name) > 64 {
		s.setFlash(w, "error", "Agent 名称不能为空且不超过 64 个字符。")
		http.Redirect(w, r, "/agents", http.StatusFound)
		return
	}
	if len(desc) > 500 {
		s.setFlash(w, "error", "描述过长。")
		http.Redirect(w, r, "/agents", http.StatusFound)
		return
	}
	token, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	agent := &model.Agent{
		ID:          store.NewID(),
		OwnerUserID: u.ID,
		Name:        name,
		Description: desc,
		Status:      model.StatusActive,
		TokenHash:   hash,
		TokenHint:   hint,
	}
	if err := s.store.CreateAgent(r.Context(), agent); err != nil {
		s.logger.Error("创建 Agent 失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "agent_created", ActorUserID: u.ID, AgentID: agent.ID, Detail: truncate(name, 64)})
	s.setOnceSecret(w, "agent_token", agent.ID, token)
	http.Redirect(w, r, "/agents/"+agent.ID+"/token", http.StatusSeeOther)
}

// pageAgentTokenShow 一次性展示 Agent Token。刷新不会再次取回。
func (s *Server) pageAgentTokenShow(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id := r.PathValue("id")
	agent, err := s.store.GetAgentByID(r.Context(), id)
	if err != nil || agent.OwnerUserID != u.ID {
		s.renderError(w, r, http.StatusNotFound, "Agent 不存在。")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	token, ok := s.popOnceSecret(w, r, "agent_token", id)
	if !ok {
		s.renderError(w, r, http.StatusGone, "该 Token 无法再次查看。原始凭证只在创建或轮换成功时展示一次；如需新凭证请轮换 Token。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "token_show", "Agent Token", "agents", map[string]any{
		"AgentID":   id,
		"AgentName": agent.Name,
		"Token":     token,
		"BaseURL":   s.cfg.BaseURL,
	})
}

func (s *Server) pageAgentRevoke(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id := r.PathValue("id")
	agent, err := s.store.GetAgentByID(r.Context(), id)
	if err != nil || agent.OwnerUserID != u.ID {
		s.renderError(w, r, http.StatusNotFound, "Agent 不存在。")
		return
	}
	if err := s.store.RevokeAgent(r.Context(), id, u.ID); err != nil {
		s.logger.Error("撤销 Agent 失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "agent_revoked", ActorUserID: u.ID, AgentID: id})
	s.setFlash(w, "success", "Agent 已撤销，其 Token 立即失效。")
	http.Redirect(w, r, "/agents", http.StatusFound)
}

func (s *Server) pageAgentRotate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id := r.PathValue("id")
	agent, err := s.store.GetAgentByID(r.Context(), id)
	if err != nil || agent.OwnerUserID != u.ID {
		s.renderError(w, r, http.StatusNotFound, "Agent 不存在。")
		return
	}
	token, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	if err := s.store.RotateAgentToken(r.Context(), id, u.ID, hash, hint); err != nil {
		s.logger.Error("轮换 Agent Token 失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "agent_token_rotated", ActorUserID: u.ID, AgentID: id})
	s.setOnceSecret(w, "agent_token", id, token)
	http.Redirect(w, r, "/agents/"+id+"/token", http.StatusSeeOther)
}
