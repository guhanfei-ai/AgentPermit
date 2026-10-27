package handler

import (
	"net/http"
	"strings"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

type loginFailure struct {
	status  int
	code    string
	message string
}

// loginWithPassword 供 HTML 与 JSON 登录共用认证、限流、会话创建及审计。
// 两类入口只负责各自的请求解析与响应格式。
func (s *Server) loginWithPassword(w http.ResponseWriter, r *http.Request, username, password string) (*model.User, *loginFailure) {
	if !s.limiter.Allow("login:" + clientIP(r)) {
		return nil, &loginFailure{http.StatusTooManyRequests, "rate_limited", "尝试过于频繁，请稍后再试。"}
	}
	username = strings.TrimSpace(username)
	u, err := s.store.GetUserByUsername(r.Context(), username)
	if err != nil && err != store.ErrNotFound {
		s.logger.Error("查询用户失败", "err", err)
		return nil, &loginFailure{http.StatusInternalServerError, "internal", "服务暂时不可用，请稍后再试。"}
	}
	if err == store.ErrNotFound || !auth.CheckPassword(u.PasswordHash, password) {
		s.audit(r, &model.AuditLog{Event: "login_failed", Outcome: "failure", Reason: "bad_credentials", Detail: truncate(username, 32)})
		return nil, &loginFailure{http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误"}
	}
	if !u.IsActive() {
		s.audit(r, &model.AuditLog{Event: "login_failed", ActorUserID: u.ID, Outcome: "failure", Reason: "user_disabled"})
		return nil, &loginFailure{http.StatusForbidden, "user_disabled", "账号已被禁用，请联系管理员。"}
	}

	// 每次登录都创建新会话和 CSRF Token，防止会话固定。
	sessionToken := auth.SessionTokenPrefix + auth.NewRandomHex(32)
	csrfToken := auth.NewRandomHex(16)
	expires := time.Now().Add(s.cfg.SessionTTL)
	if err := s.store.CreateSession(r.Context(), auth.HashToken(sessionToken), u.ID, csrfToken, expires); err != nil {
		s.logger.Error("创建会话失败", "err", err)
		return nil, &loginFailure{http.StatusInternalServerError, "internal", "服务暂时不可用，请稍后再试。"}
	}
	s.setCookie(w, cookieSession, sessionToken, int(s.cfg.SessionTTL.Seconds()))
	s.bindRuntime(r, u.ID)
	s.audit(r, &model.AuditLog{Event: "login_success", ActorUserID: u.ID})
	return u, nil
}

// logoutSession 撤销服务端会话后再清除新旧 Cookie，避免仅清客户端却留下有效会话。
func (s *Server) logoutSession(w http.ResponseWriter, r *http.Request) error {
	if sess := sessionFrom(r.Context()); sess != nil {
		if err := s.store.RevokeSession(r.Context(), sess.TokenHash); err != nil {
			s.logger.Error("撤销会话失败", "err", err)
			return err
		}
	}
	clearCookies(w, sessionCookieNames...)
	if u := userFrom(r.Context()); u != nil {
		s.audit(r, &model.AuditLog{Event: "logout", ActorUserID: u.ID})
	}
	return nil
}
