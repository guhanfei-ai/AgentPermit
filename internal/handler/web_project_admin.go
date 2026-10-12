package handler

import (
	"errors"
	"net/http"
	"strings"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// 禁言选择器只包含管理所需元数据，不把 Token 摘要或提示交给页面。
type projectBanCredentialOption struct {
	ID     string
	Name   string
	Status string
}

type projectBanTarget struct {
	Username    string
	DisplayName string
	Status      string
	Credentials []projectBanCredentialOption
}

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
	username := strings.TrimSpace(r.URL.Query().Get("ban_username"))
	var target *projectBanTarget
	lookupError := ""
	if len(username) > 64 {
		lookupError = "用户名不能超过 64 个字符。"
	} else if username != "" {
		account, err := s.store.GetUserByUsername(r.Context(), username)
		if errors.Is(err, store.ErrNotFound) {
			lookupError = "未找到这个账号，请核对用户名。"
		} else if err != nil {
			s.logger.Error("查询禁言目标账号失败", "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
			return
		} else {
			credentials, err := s.store.ListAgentCredentialsByOwner(r.Context(), account.ID)
			if err != nil {
				s.logger.Error("查询禁言目标凭证失败", "err", err)
				s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
				return
			}
			target = &projectBanTarget{Username: account.Username, DisplayName: account.DisplayName, Status: account.Status}
			for _, credential := range credentials {
				target.Credentials = append(target.Credentials, projectBanCredentialOption{
					ID: credential.ID, Name: credential.Name, Status: credential.Status,
				})
			}
		}
	}
	s.renderPage(w, r, http.StatusOK, "project_admin", "项目管理 · "+p.Name, "project", map[string]any{
		"Project":           p,
		"Admins":            admins,
		"Bans":              bans,
		"IsPlatformAdmin":   u.IsAdmin(),
		"BanTarget":         target,
		"BanLookupUsername": username,
		"BanLookupError":    lookupError,
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

// pageProjectBanAdd 先确定账号，再按显式 scope 限制账号或单条凭证的发言。
// 未携带 scope 的旧表单沿用 agent_id 空值为账号级的约定；读取不受禁言影响。
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
	credentialID := strings.TrimSpace(r.PostFormValue("agent_id"))
	scope := strings.TrimSpace(r.PostFormValue("scope"))
	if _, explicit := r.PostForm["scope"]; !explicit {
		// 旧网页表单的兼容路径，不改变已有请求语义。
		scope = "user"
		if credentialID != "" {
			scope = "credential"
		}
	}
	if (scope != "user" && scope != "credential") ||
		(scope == "user" && credentialID != "") || (scope == "credential" && credentialID == "") {
		s.setFlash(w, "error", "请选择明确的禁言范围；账号级不能携带凭证 ID，单凭证范围必须选择一条凭证。")
		http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusFound)
		return
	}
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
	if credentialID != "" {
		credential, err := s.store.GetAgentCredentialByID(r.Context(), credentialID)
		if err != nil || credential.OwnerUserID != target.ID {
			s.setFlash(w, "error", "凭证不存在或不属于所选账号。")
			http.Redirect(w, r, "/projects/"+p.Slug+"/admin", http.StatusFound)
			return
		}
	}
	ban := &model.ProjectBan{
		ProjectID:    p.ID,
		UserID:       target.ID,
		CredentialID: credentialID,
		Reason:       reason,
		BannedBy:     u.ID,
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
	if credentialID == "" {
		event = "project_user_banned"
	}
	s.audit(r, &model.AuditLog{Event: event, ActorUserID: u.ID, ProjectID: p.ID, SubjectUserID: target.ID, CredentialID: credentialID, Reason: reason, Detail: truncate(username, 64)})
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
	credentialID := r.PostFormValue("agent_id")
	if err := s.store.RemoveProjectBan(r.Context(), p.ID, userID, credentialID); err != nil {
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
	if credentialID == "" {
		event = "project_user_unbanned"
	}
	s.audit(r, &model.AuditLog{Event: event, ActorUserID: u.ID, ProjectID: p.ID, SubjectUserID: userID, CredentialID: credentialID})
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
