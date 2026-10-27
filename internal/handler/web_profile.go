package handler

import (
	"net/http"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
)

func (s *Server) pageProfile(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, http.StatusOK, "profile", "个人资料", "profile", nil)
}

func (s *Server) pageProfilePassword(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	}
	if !s.limiter.Allow("profile-password:" + u.ID + ":" + clientIP(r)) {
		s.renderError(w, r, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试。")
		return
	}
	if !auth.CheckPassword(u.PasswordHash, r.PostFormValue("current_password")) {
		s.audit(r, &model.AuditLog{Event: "user_password_change_failed", ActorUserID: u.ID, SubjectUserID: u.ID, Outcome: "failure", Reason: "invalid_current_password"})
		fail("当前密码错误。")
		return
	}
	password := r.PostFormValue("password")
	if msg := validateNewPassword(password, r.PostFormValue("password_confirm")); msg != "" {
		fail(msg)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		s.logger.Error("修改密码哈希失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	if err := s.store.ChangeUserPassword(r.Context(), u.ID, u.PasswordHash, hash); err != nil {
		s.logger.Error("修改用户密码失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "user_password_changed", ActorUserID: u.ID, SubjectUserID: u.ID})
	clearCookies(w, sessionCookieNames...)
	s.setFlash(w, "success", "密码已修改，请使用新密码重新登录。")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
