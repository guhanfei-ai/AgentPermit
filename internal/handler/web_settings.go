package handler

import (
	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"net/http"
)

func (s *Server) pageAdminSettings(w http.ResponseWriter, r *http.Request) {
	hash, err := s.store.GetHolidayUnlockPasswordHash(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.renderPage(w, r, http.StatusOK, "admin_settings", "系统设置", "admin-settings", map[string]any{"Configured": hash != ""})
}

func (s *Server) pageAdminHolidayUnlockPassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if !s.limiter.Allow("holiday-password-change:" + u.ID + ":" + clientIP(r)) {
		s.renderError(w, r, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试。")
		return
	}
	hash, err := s.store.GetHolidayUnlockPasswordHash(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	// 首次配置用管理员登录密码确认；之后须提供当前解锁密码。
	verificationHash := hash
	if verificationHash == "" {
		verificationHash = u.PasswordHash
	}
	if !auth.CheckPassword(verificationHash, r.PostFormValue("current_password")) {
		s.audit(r, &model.AuditLog{Event: "holiday_unlock_password_change_failed", ActorUserID: u.ID, Outcome: "failure", Reason: "invalid_current_password"})
		s.renderError(w, r, http.StatusForbidden, "当前密码错误，设置未修改。")
		return
	}
	password := r.PostFormValue("password")
	if msg := validateNewPassword(password, r.PostFormValue("password_confirm")); msg != "" {
		s.renderError(w, r, http.StatusUnprocessableEntity, msg)
		return
	}
	newHash, err := auth.HashPassword(password)
	if err == nil {
		err = s.store.UpdateHolidayUnlockPasswordHash(r.Context(), newHash)
	}
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "holiday_unlock_password_changed", ActorUserID: u.ID})
	s.setFlash(w, "success", "解锁密码已设置，新密码立即生效。")
	http.Redirect(w, r, "/admin/settings", http.StatusSeeOther)
}
