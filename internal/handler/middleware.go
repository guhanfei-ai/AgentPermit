package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
)

const maxBodyBytes = 1 << 20 // 1 MiB

type ctxAnonCSRFType struct{}

var ctxAnonCSRF = ctxAnonCSRFType{}

// baseMiddleware 应用到全部请求：RequestID → 访问日志 → Panic Recovery → 请求体限制。
func (s *Server) baseMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := newRequestID()
		ctx := withRequestID(r.Context(), reqID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", reqID)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if p := recover(); p != nil {
				s.logger.Error("panic 恢复", "panic", p, "path", r.URL.Path, "request_id", reqID)
				// 根据路径区分 API 与页面响应格式
				if isAPIPath(r.URL.Path) {
					s.jsonError(rec, r, http.StatusInternalServerError, "internal", "服务器内部错误")
				} else if !rec.wrote {
					http.Error(rec, "服务器内部错误", http.StatusInternalServerError)
				}
				s.logAccess(rec, r, start, true)
				return
			}
			s.logAccess(rec, r, start, false)
		}()

		r.Body = http.MaxBytesReader(rec, r.Body, maxBodyBytes)
		next.ServeHTTP(rec, r)
	})
}

func (s *Server) logAccess(rec *statusRecorder, r *http.Request, start time.Time, panicked bool) {
	s.logger.Info("access",
		"method", r.Method,
		"path", r.URL.Path,
		"status", rec.status,
		"remote", r.RemoteAddr,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestIDFrom(r.Context()),
		"panicked", panicked,
	)
}

func isAPIPath(p string) bool {
	return len(p) >= 5 && p[:5] == "/api/"
}

func newRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

// sessionMiddleware 解析会话 Cookie，校验有效期、撤销状态与用户状态。
// 用户被禁用后会话立即不可用。GET 请求时确保匿名 CSRF Cookie 存在。
// 会话 Cookie 优先读新名 ap_session，回退更名前的 aad_session（登录态不丢失）。
func (s *Server) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionCookie := ""
		if c, err := r.Cookie(cookieSession); err == nil && c.Value != "" {
			sessionCookie = c.Value
		} else if c, err := r.Cookie(legacyCookieSession); err == nil && c.Value != "" {
			sessionCookie = c.Value
		}
		if sessionCookie != "" {
			tokenHash := auth.HashToken(sessionCookie)
			sess, err := s.store.GetSessionByTokenHash(r.Context(), tokenHash)
			if err == nil && sess.RevokedAt == nil && time.Now().Before(sess.ExpiresAt) {
				u, err := s.store.GetUserByID(r.Context(), sess.UserID)
				if err == nil && u.IsActive() {
					r = r.WithContext(withUser(r.Context(), u, sess))
				} else {
					// 用户已禁用：会话立即失效
					s.setCookie(w, cookieSession, "", -1)
					s.setCookie(w, legacyCookieSession, "", -1)
				}
			} else if err == nil && sess.RevokedAt != nil {
				s.setCookie(w, cookieSession, "", -1)
				s.setCookie(w, legacyCookieSession, "", -1)
			}
		}
		// 匿名 CSRF（双提交 Cookie，登录/注册表单用）。
		// 同一请求内新生成的值也写入 ctx，保证首屏表单可嵌入。
		// 兼容读取更名前的旧 Cookie 值，避免登录页表单校验失败。
		if r.Method == http.MethodGet {
			var anonCSRF string
			if c, err := r.Cookie(cookieCSRF); err == nil && c.Value != "" {
				anonCSRF = c.Value
			} else if c, err := r.Cookie(legacyCookieCSRF); err == nil && c.Value != "" {
				anonCSRF = c.Value
				s.setCookie(w, cookieCSRF, anonCSRF, 3600)
			} else {
				anonCSRF = auth.NewRandomHex(16)
				s.setCookie(w, cookieCSRF, anonCSRF, 3600)
			}
			r = r.WithContext(context.WithValue(r.Context(), ctxAnonCSRF, anonCSRF))
		}
		next.ServeHTTP(w, r)
	})
}

// csrfTokenFor 返回当前请求应嵌入表单的 CSRF Token。
// 已登录：会话内 Token；匿名：双提交 Cookie（或本请求新生成的值）。
func (s *Server) csrfTokenFor(r *http.Request, u *model.User) string {
	if u != nil {
		if sess := sessionFrom(r.Context()); sess != nil {
			return sess.CSRFToken
		}
	}
	if v, ok := r.Context().Value(ctxAnonCSRF).(string); ok && v != "" {
		return v
	}
	if c, err := r.Cookie(cookieCSRF); err == nil && c.Value != "" {
		return c.Value
	}
	// 兼容更名前的匿名 CSRF Cookie
	if c, err := r.Cookie(legacyCookieCSRF); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// csrfProtect 校验全部非 GET 网页请求（API 走 Bearer，不经此中间件）。
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			s.renderError(w, r, http.StatusBadRequest, "请求格式错误")
			return
		}
		formToken := r.PostFormValue("csrf_token")
		expected := s.csrfTokenFor(r, userFrom(r.Context()))
		if expected == "" || !auth.EqualSecret(formToken, expected) {
			s.logger.Warn("CSRF 校验失败", "path", r.URL.Path, "request_id", requestIDFrom(r.Context()))
			s.renderError(w, r, http.StatusForbidden, "请求校验失败（CSRF Token 无效），请返回重新操作。")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireLogin 要求已登录，否则跳转登录页。
func (s *Server) requireLogin(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r.Context()) == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// requireAdmin 要求管理员。
func (s *Server) requireAdmin(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return s.requireLogin(func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r.Context())
		if !u.IsAdmin() {
			s.renderError(w, r, http.StatusForbidden, "需要管理员权限。")
			return
		}
		next(w, r)
	})
}
