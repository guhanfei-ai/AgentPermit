package handler

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{3,32}$`)

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
	s.renderPage(w, r, http.StatusOK, "login", "登录", "", map[string]any{"AllowRegistration": s.cfg.AllowRegistration})
}

func (s *Server) pageLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.Allow("login:" + clientIP(r)) {
		s.renderError(w, r, http.StatusTooManyRequests, "尝试过于频繁，请稍后再试。")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")

	u, err := s.store.GetUserByUsername(r.Context(), username)
	// 统一错误提示，不区分用户不存在与密码错误
	if err == store.ErrNotFound || !auth.CheckPassword(u.PasswordHash, password) {
		s.audit(r, &model.AuditLog{Event: "login_failed", Outcome: "failure", Reason: "bad_credentials", Detail: truncate(username, 32)})
		s.setFlash(w, "error", "用户名或密码错误")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err != nil {
		s.logger.Error("查询用户失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	if !u.IsActive() {
		s.audit(r, &model.AuditLog{Event: "login_failed", ActorUserID: u.ID, Outcome: "failure", Reason: "user_disabled"})
		s.renderError(w, r, http.StatusForbidden, "账号已被禁用，请联系管理员。")
		return
	}

	// 登录成功：新建 Session（防 Session 固定），Cookie 只放高熵随机 Token
	sessionToken := auth.SessionTokenPrefix + auth.NewRandomHex(32)
	csrfToken := auth.NewRandomHex(16)
	expires := time.Now().Add(s.cfg.SessionTTL)
	if err := s.store.CreateSession(r.Context(), auth.HashToken(sessionToken), u.ID, csrfToken, expires); err != nil {
		s.logger.Error("创建会话失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.setCookie(w, cookieSession, sessionToken, int(s.cfg.SessionTTL.Seconds()))
	s.audit(r, &model.AuditLog{Event: "login_success", ActorUserID: u.ID})
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
	if !usernamePattern.MatchString(username) {
		fail("用户名仅允许字母、数字、下划线、连字符，长度 3-32。")
		return
	}
	if displayName == "" || len(displayName) > 64 {
		fail("显示名不能为空且不超过 64 个字符。")
		return
	}
	if len(password) < 8 || len(password) > 128 {
		fail("密码长度至少 8 位。")
		return
	}
	if password != confirm {
		fail("两次输入的密码不一致。")
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
	u := userFrom(r.Context())
	if sess := sessionFrom(r.Context()); sess != nil {
		if err := s.store.RevokeSession(r.Context(), sess.TokenHash); err != nil {
			s.logger.Error("撤销会话失败", "err", err)
		}
	}
	s.setCookie(w, cookieSession, "", -1)
	if u != nil {
		s.audit(r, &model.AuditLog{Event: "logout", ActorUserID: u.ID})
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
