package handler

import (
	"net/http"
	"strings"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
)

type accessPageData struct {
	Capability    *model.Capability
	Denylist      []*model.ListEntry
	Allowlist     []*model.ListEntry
	Cred          *model.ServiceCredential
	Query         string
	SearchResults []*model.User
}

func (s *Server) pageCapabilityAccess(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	ctx := r.Context()
	deny, err := s.store.ListDeny(ctx, c.ID)
	if err != nil {
		s.logger.Error("查询黑名单失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	allow, err := s.store.ListAllow(ctx, c.ID)
	if err != nil {
		s.logger.Error("查询白名单失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	cred, err := s.store.GetServiceCredentialByCapability(ctx, c.ID)
	if err != nil {
		s.logger.Error("查询服务凭证失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	data := &accessPageData{Capability: c, Denylist: deny, Allowlist: allow, Cred: cred}
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		data.Query = q
		results, err := s.store.SearchUsers(ctx, q, u.ID, 10)
		if err != nil {
			s.logger.Error("搜索用户失败", "err", err)
		} else {
			data.SearchResults = results
		}
	}
	s.renderPage(w, r, http.StatusOK, "capability_access", "权限管理", "capabilities", data)
}

func (s *Server) pageAccessMode(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	mode := r.PostFormValue("access_mode")
	if mode != model.AccessModeTeam && mode != model.AccessModeAllowlist {
		s.setFlash(w, "error", "访问模式不合法。")
		http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
		return
	}
	if err := s.store.SetAccessMode(r.Context(), c.ID, u.ID, mode); err != nil {
		s.logger.Error("切换访问模式失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_access_mode_changed", ActorUserID: u.ID, CapabilityID: c.ID, Reason: mode})
	s.setFlash(w, "success", "访问模式已切换为 "+mode+"。")
	http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
}

// listTarget 校验待加入名单的目标用户。
func (s *Server) listTarget(w http.ResponseWriter, r *http.Request, u *model.User, c *model.Capability) *model.User {
	userID := r.PostFormValue("user_id")
	target, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		s.setFlash(w, "error", "目标用户不存在。")
		http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
		return nil
	}
	if target.ID == u.ID {
		// 能力所有者不可被加入黑名单（所有者本身永远有权访问）
		s.setFlash(w, "error", "不能把能力所有者自己加入黑名单。")
		http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
		return nil
	}
	return target
}

func (s *Server) pageDenyAdd(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	target := s.listTarget(w, r, u, c)
	if target == nil {
		return
	}
	if err := s.store.AddDeny(r.Context(), c.ID, target.ID); err != nil {
		s.logger.Error("加入黑名单失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_denylist_added", ActorUserID: u.ID, CapabilityID: c.ID, SubjectUserID: target.ID, Detail: truncate(target.Username, 32)})
	s.setFlash(w, "success", "已将 "+target.DisplayName+"（"+target.Username+"）加入黑名单，其所有 Agent 立即无法调用该能力。")
	http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
}

func (s *Server) pageDenyRemove(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	targetID := r.PostFormValue("user_id")
	if err := s.store.RemoveDeny(r.Context(), c.ID, targetID); err != nil {
		s.setFlash(w, "error", "该用户不在黑名单中。")
		http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_denylist_removed", ActorUserID: u.ID, CapabilityID: c.ID, SubjectUserID: targetID})
	s.setFlash(w, "success", "已从黑名单移除。")
	http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
}

func (s *Server) pageAllowAdd(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	target := s.listTarget(w, r, u, c)
	if target == nil {
		return
	}
	if err := s.store.AddAllow(r.Context(), c.ID, target.ID); err != nil {
		s.logger.Error("加入白名单失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_allowlist_added", ActorUserID: u.ID, CapabilityID: c.ID, SubjectUserID: target.ID, Detail: truncate(target.Username, 32)})
	modeNote := ""
	if c.AccessMode != model.AccessModeAllowlist {
		modeNote = "注意：当前仍是 team 模式，白名单尚未生效；需要手动切换访问模式。"
	}
	s.setFlash(w, "success", "已加入白名单。"+modeNote)
	http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
}

func (s *Server) pageAllowRemove(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	targetID := r.PostFormValue("user_id")
	if err := s.store.RemoveAllow(r.Context(), c.ID, targetID); err != nil {
		s.setFlash(w, "error", "该用户不在白名单中。")
		http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_allowlist_removed", ActorUserID: u.ID, CapabilityID: c.ID, SubjectUserID: targetID})
	s.setFlash(w, "success", "已从白名单移除。")
	http.Redirect(w, r, "/capabilities/"+c.ID+"/access", http.StatusFound)
}

func (s *Server) pageServiceTokenRotate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	token, hash, hint := auth.NewToken(auth.ServiceTokenPrefix)
	if err := s.store.RotateServiceToken(r.Context(), c.ID, u.ID, hash, hint); err != nil {
		s.logger.Error("轮换 Service Token 失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_service_token_rotated", ActorUserID: u.ID, CapabilityID: c.ID})
	s.setOnceSecret(w, "service_token", c.ID, token)
	http.Redirect(w, r, "/capabilities/"+c.ID+"/service-token", http.StatusSeeOther)
}

// pageServiceTokenShow 一次性展示 Service Token。
func (s *Server) pageServiceTokenShow(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	token, ok := s.popOnceSecret(w, r, "service_token", c.ID)
	if !ok {
		s.renderError(w, r, http.StatusGone, "该 Service Token 无法再次查看。原始凭证只在创建或轮换成功时展示一次；如需新凭证请轮换。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "service_token_show", "Service Token", "capabilities", map[string]any{
		"CapabilityID":   c.ID,
		"CapabilityName": c.Name,
		"Token":          token,
		"BaseURL":        s.cfg.BaseURL,
	})
}
