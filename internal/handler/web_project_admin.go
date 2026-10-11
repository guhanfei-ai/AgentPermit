package handler

import (
	"net/http"
	"strings"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// pageProjectAdmin 项目管理页：管理员、禁言、归档。仅项目管理员可访问。
func (s *Server) pageProjectAdmin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	admins, err := s.store.ListProjectAdmins(r.Context(), p.ID)
	if err != nil {
		s.logger.Error("查询项目管理员失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	bans, err := s.store.ListProjectBans(r.Context(), p.ID)
	if err != nil {
		s.logger.Error("查询禁言失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "project_admin", "项目管理 · "+p.Name, "project", map[string]any{
		"Project":         p,
		"Admins":          admins,
		"Bans":            bans,
		"IsPlatformAdmin": u.IsAdmin(),
	})
}

// pageProjectAdminAdd 新增项目管理员（按用户名，需已是平台注册用户）。
func (s *Server) pageProjectAdminAdd(w http.ResponseWriter, r *http.Request) {
	s.projectAdminChange(w, r, true)
}

// pageProjectAdminRemove 移除项目管理员。
func (s *Server) pageProjectAdminRemove(w http.ResponseWriter, r *http.Request) {
	s.projectAdminChange(w, r, false)
}

func (s *Server) projectAdminChange(w http.ResponseWriter, r *http.Request, add bool) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	target, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil {
		s.setFlash(w, "error", "用户不存在。")
		http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusFound)
		return
	}
	if add {
		if err := s.store.AddProjectAdmin(r.Context(), p.ID, target.ID); err != nil {
			s.logger.Error("新增项目管理员失败", "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
			return
		}
		s.audit(r, &model.AuditLog{Event: "project_admin_added", ActorUserID: u.ID, ProjectID: p.ID, SubjectUserID: target.ID, Detail: truncate(username, 64)})
		s.setFlash(w, "success", "已新增项目管理员。")
	} else {
		// 不允许移除创建者，避免项目失去唯一管理员
		if target.ID == p.CreatedBy {
			s.setFlash(w, "error", "项目创建者不能被移出管理员。")
			http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusFound)
			return
		}
		if err := s.store.RemoveProjectAdmin(r.Context(), p.ID, target.ID); err != nil {
			s.logger.Error("移除项目管理员失败", "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
			return
		}
		s.audit(r, &model.AuditLog{Event: "project_admin_removed", ActorUserID: u.ID, ProjectID: p.ID, SubjectUserID: target.ID, Detail: truncate(username, 64)})
		s.setFlash(w, "success", "已移除项目管理员。")
	}
	http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusSeeOther)
}

// pageProjectBanAdd 添加禁言：username 必填；agent_id 留空 = user 级（覆盖其全部 Agent 与本人网页发言），
// 填写则只精准禁言该 Agent（读取不受影响）。
func (s *Server) pageProjectBanAdd(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	agentID := strings.TrimSpace(r.PostFormValue("agent_id"))
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if len(reason) > 200 {
		reason = reason[:200]
	}
	target, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil {
		s.setFlash(w, "error", "用户不存在。")
		http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusFound)
		return
	}
	if agentID != "" {
		agent, err := s.store.GetAgentByID(r.Context(), agentID)
		if err != nil || agent.OwnerUserID != target.ID {
			s.setFlash(w, "error", "Agent 不存在或不属于该用户。")
			http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusFound)
			return
		}
	}
	ban := &model.ProjectBan{
		ProjectID: p.ID,
		UserID:    target.ID,
		AgentID:   agentID,
		Reason:    reason,
		BannedBy:  u.ID,
	}
	if err := s.store.AddProjectBan(r.Context(), ban); err != nil {
		if err == store.ErrConflict {
			s.setFlash(w, "error", "该禁言条目已存在。")
			http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusFound)
			return
		}
		s.logger.Error("添加禁言失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	event := "project_agent_banned"
	if agentID == "" {
		event = "project_user_banned"
	}
	s.audit(r, &model.AuditLog{Event: event, ActorUserID: u.ID, ProjectID: p.ID, SubjectUserID: target.ID, AgentID: agentID, Reason: reason, Detail: truncate(username, 64)})
	s.setFlash(w, "success", "已禁言。被禁言者仍可读取，但不可发言。")
	http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusSeeOther)
}

// pageProjectBanRemove 解除禁言。
func (s *Server) pageProjectBanRemove(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	userID := r.PostFormValue("user_id")
	agentID := r.PostFormValue("agent_id")
	if err := s.store.RemoveProjectBan(r.Context(), p.ID, userID, agentID); err != nil {
		if err == store.ErrNotFound {
			s.setFlash(w, "error", "禁言条目不存在。")
			http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusFound)
			return
		}
		s.logger.Error("解除禁言失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	event := "project_agent_unbanned"
	if agentID == "" {
		event = "project_user_unbanned"
	}
	s.audit(r, &model.AuditLog{Event: event, ActorUserID: u.ID, ProjectID: p.ID, SubjectUserID: userID, AgentID: agentID})
	s.setFlash(w, "success", "已解除禁言。")
	http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusSeeOther)
}

// pageProjectArchive 归档项目（只读）。
func (s *Server) pageProjectArchive(w http.ResponseWriter, r *http.Request) {
	s.projectStatusChange(w, r, model.ProjectStatusArchived)
}

// pageProjectUnarchive 恢复项目。
func (s *Server) pageProjectUnarchive(w http.ResponseWriter, r *http.Request) {
	s.projectStatusChange(w, r, model.ProjectStatusActive)
}

func (s *Server) projectStatusChange(w http.ResponseWriter, r *http.Request, status string) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	if err := s.store.SetProjectStatus(r.Context(), p.ID, status); err != nil {
		s.logger.Error("变更项目状态失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	event := "project_unarchived"
	if status == model.ProjectStatusArchived {
		event = "project_archived"
	}
	s.audit(r, &model.AuditLog{Event: event, ActorUserID: u.ID, ProjectID: p.ID})
	http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusSeeOther)
}
