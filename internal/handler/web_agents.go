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

func (s *Server) pageCredentials(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	credentials, err := s.store.ListAgentCredentialsByOwner(r.Context(), u.ID)
	if err != nil {
		s.logger.Error("查询调用凭证失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "agents", "我的调用凭证", "agents", map[string]any{"Credentials": credentials})
}

func (s *Server) pageCredentialCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if name == "" || len(name) > 64 {
		s.setFlash(w, "error", "凭证用途名称不能为空且不超过 64 个字符。")
		http.Redirect(w, r, "/agents", http.StatusFound)
		return
	}
	if len(desc) > 500 {
		s.setFlash(w, "error", "描述过长。")
		http.Redirect(w, r, "/agents", http.StatusFound)
		return
	}
	token, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	credential := &model.AgentCredential{
		ID:          store.NewID(),
		OwnerUserID: u.ID,
		Name:        name,
		Description: desc,
		Status:      model.StatusActive,
		TokenHash:   hash,
		TokenHint:   hint,
	}
	if err := s.store.CreateAgentCredential(r.Context(), credential); err != nil {
		s.logger.Error("创建调用凭证失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "agent_created", ActorUserID: u.ID, CredentialID: credential.ID, Detail: truncate(name, 64)})
	s.setOnceSecret(w, "agent_token", credential.ID, token)
	http.Redirect(w, r, "/agents/"+credential.ID+"/token", http.StatusSeeOther)
}

// pageCredentialTokenShow 一次性展示调用凭证的 Token。刷新不会再次取回。
func (s *Server) pageCredentialTokenShow(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id := r.PathValue("id")
	credential, err := s.store.GetAgentCredentialByID(r.Context(), id)
	if err != nil || credential.OwnerUserID != u.ID {
		s.renderError(w, r, http.StatusNotFound, "凭证不存在。")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	token, ok := s.popOnceSecret(w, r, "agent_token", id)
	if !ok {
		s.renderError(w, r, http.StatusGone, "该 Token 无法再次查看。原始凭证只在创建或轮换成功时展示一次；如需新凭证请轮换 Token。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "token_show", "调用凭证一次性展示", "agents", map[string]any{
		"CredentialID":   id,
		"CredentialName": credential.Name,
		"Token":          token,
		"BaseURL":        s.cfg.BaseURL,
	})
}

func (s *Server) pageCredentialRevoke(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id := r.PathValue("id")
	credential, err := s.store.GetAgentCredentialByID(r.Context(), id)
	if err != nil || credential.OwnerUserID != u.ID {
		s.renderError(w, r, http.StatusNotFound, "凭证不存在。")
		return
	}
	if err := s.store.RevokeAgentCredential(r.Context(), id, u.ID); err != nil {
		s.logger.Error("撤销调用凭证失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "agent_revoked", ActorUserID: u.ID, CredentialID: id})
	s.setFlash(w, "success", "该凭证已撤销，对应 Token 立即失效；账号名下其他凭证不受影响。")
	http.Redirect(w, r, "/agents", http.StatusFound)
}

func (s *Server) pageCredentialRotate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id := r.PathValue("id")
	credential, err := s.store.GetAgentCredentialByID(r.Context(), id)
	if err != nil || credential.OwnerUserID != u.ID {
		s.renderError(w, r, http.StatusNotFound, "凭证不存在。")
		return
	}
	token, hash, hint := auth.NewToken(auth.AgentTokenPrefix)
	if err := s.store.RotateAgentCredentialToken(r.Context(), id, u.ID, hash, hint); err != nil {
		s.logger.Error("轮换调用凭证失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "agent_token_rotated", ActorUserID: u.ID, CredentialID: id})
	s.setOnceSecret(w, "agent_token", id, token)
	http.Redirect(w, r, "/agents/"+id+"/token", http.StatusSeeOther)
}
