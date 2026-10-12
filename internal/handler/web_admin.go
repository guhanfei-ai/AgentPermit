package handler

import (
	"net/http"

	"agentpermit/internal/model"
)

func (s *Server) pageAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.logger.Error("查询用户失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "admin_users", "用户管理", "admin", map[string]any{
		"Users": users,
		"Me":    userFrom(r.Context()),
	})
}

func (s *Server) pageAdminDisable(w http.ResponseWriter, r *http.Request) {
	s.setAdminUserStatus(w, r, model.StatusDisabled, "user_disabled", "账号已禁用，网页会话已撤销，名下调用凭证暂停访问；凭证未被永久撤销。")
}

func (s *Server) pageAdminEnable(w http.ResponseWriter, r *http.Request) {
	s.setAdminUserStatus(w, r, model.StatusActive, "user_enabled", "账号已启用，仍有效的调用凭证恢复可用；网页登录需重新登录。")
}

func (s *Server) setAdminUserStatus(w http.ResponseWriter, r *http.Request, status, event, msg string) {
	me := userFrom(r.Context())
	targetID := r.PathValue("id")
	if targetID == me.ID {
		s.setFlash(w, "error", "不能禁用当前登录的管理员自己。")
		http.Redirect(w, r, "/admin/users", http.StatusFound)
		return
	}
	target, err := s.store.GetUserByID(r.Context(), targetID)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "用户不存在。")
		return
	}
	if err := s.store.SetUserStatus(r.Context(), targetID, status); err != nil {
		s.logger.Error("更新用户状态失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	if status == model.StatusDisabled {
		// 禁用后撤销全部现有会话；调用凭证由策略层实时拒绝，重新启用不复活已撤销的凭证
		if err := s.store.RevokeSessionsForUser(r.Context(), targetID); err != nil {
			s.logger.Error("撤销会话失败", "err", err)
		}
	}
	s.audit(r, &model.AuditLog{Event: event, ActorUserID: me.ID, SubjectUserID: targetID, Detail: truncate(target.Username, 32)})
	s.setFlash(w, "success", msg)
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}
