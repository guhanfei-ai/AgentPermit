package handler

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)

// validateNewUser 供公开注册和管理员开户共用，角色由各入口固定，不能由表单指定。
func validateNewUser(username, displayName, password, confirm string) string {
	if !usernamePattern.MatchString(username) {
		return "用户名仅允许字母、数字、下划线、连字符，长度 3-32。"
	}
	if displayName == "" || utf8.RuneCountInString(displayName) > 64 {
		return "显示名不能为空且不超过 64 个字符。"
	}
	return validateNewPassword(password, confirm)
}

func validateNewPassword(password, confirm string) string {
	// bcrypt 的密码上限是 72 字节；提前返回明确提示，避免开户时变成内部错误。
	if len(password) < auth.MinPasswordLen || len(password) > auth.MaxPasswordLen {
		return fmt.Sprintf("密码长度须为 %d-%d 字节，中文等字符会占用多个字节。", auth.MinPasswordLen, auth.MaxPasswordLen)
	}
	if password != confirm {
		return "两次输入的密码不一致。"
	}
	return ""
}

// clientIP 不信任 X-Forwarded-For，仅取 RemoteAddr（限流 key 用）。
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}

func (s *Server) pageLogin(w http.ResponseWriter, r *http.Request) {
	if userFrom(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.renderPage(w, r, http.StatusOK, "login", "登录", "", nil)
}

func (s *Server) pageLoginSubmit(w http.ResponseWriter, r *http.Request) {
	_, failure := s.loginWithPassword(w, r, r.PostFormValue("username"), r.PostFormValue("password"))
	if failure != nil {
		if failure.code == "invalid_credentials" {
			s.setFlash(w, "error", failure.message)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		s.renderError(w, r, failure.status, failure.message)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) pageRegister(w http.ResponseWriter, r *http.Request) {
	if userFrom(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if !s.cfg.AllowRegistration {
		s.setFlash(w, "error", "注册已关闭，请联系管理员创建账号。")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.renderPage(w, r, http.StatusOK, "register", "注册", "", nil)
}

func (s *Server) pageRegisterSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowRegistration {
		s.setFlash(w, "error", "注册已关闭。")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if !s.limiter.Allow("register:" + clientIP(r)) {
		s.renderError(w, r, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试。")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("password_confirm")

	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/register", http.StatusFound)
	}
	if msg := validateNewUser(username, displayName, password, confirm); msg != "" {
		fail(msg)
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	u := &model.User{
		ID:           store.NewID(),
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: hash,
		Role:         model.UserRoleUser,
		Status:       model.StatusActive,
	}
	if err := s.store.CreateUser(r.Context(), u); err != nil {
		if err == store.ErrConflict {
			fail("用户名已被占用。")
			return
		}
		s.logger.Error("创建用户失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "user_registered", ActorUserID: u.ID, Detail: truncate(username, 32)})
	s.setFlash(w, "success", "注册成功，请登录。")
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) pageLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.logoutSession(w, r); err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.setFlash(w, "success", "已退出登录。")
	http.Redirect(w, r, "/login", http.StatusFound)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
