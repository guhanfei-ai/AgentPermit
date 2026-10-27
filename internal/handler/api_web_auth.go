package handler

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
)

// webUserJSON 显式列出真人可见字段，不序列化包含密码摘要的存储模型。
type webUserJSON struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Status      string `json:"status"`
}

func webUser(u *model.User) webUserJSON {
	return webUserJSON{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Status: u.Status}
}

func (s *Server) requireWebAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := userFrom(r.Context())
		if u == nil {
			s.jsonError(w, r, http.StatusUnauthorized, "unauthorized", "请先登录")
			return
		}
		s.bindRuntime(r, u.ID)
		next(w, r)
	}
}

// csrfProtectJSON 只从 Header 读取 CSRF，不解析 JSON 为表单，也不返回 HTML 错误。
func (s *Server) csrfProtectJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := s.csrfTokenFor(r, userFrom(r.Context()))
		if expected == "" || !auth.EqualSecret(r.Header.Get("X-CSRF-Token"), expected) {
			s.jsonError(w, r, http.StatusForbidden, "csrf_invalid", "请求校验失败（CSRF Token 无效）")
			return
		}
		next(w, r)
	}
}

// decodeWebJSON 要求单个 JSON 对象，拒绝未知字段、尾随内容与超限请求。
func (s *Server) decodeWebJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		s.jsonError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "请求必须使用 application/json")
		return false
	}
	invalid := func(err error) bool {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.jsonError(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "请求体过大")
		} else {
			s.jsonError(w, r, http.StatusBadRequest, "invalid_request", "请求体必须是有效的单个 JSON 对象")
		}
		return false
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return invalid(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return invalid(err)
	}
	return true
}

func (s *Server) webAPICSRF(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusOK, map[string]string{"csrf_token": s.csrfTokenFor(r, userFrom(r.Context()))})
}

func (s *Server) webAPILogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !s.decodeWebJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Username) == "" || input.Password == "" {
		s.jsonError(w, r, http.StatusBadRequest, "invalid_request", "用户名与密码不能为空")
		return
	}
	u, failure := s.loginWithPassword(w, r, input.Username, input.Password)
	if failure != nil {
		s.jsonError(w, r, failure.status, failure.code, failure.message)
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]any{"user": webUser(u)})
}

func (s *Server) webAPILogout(w http.ResponseWriter, r *http.Request) {
	if err := s.logoutSession(w, r); err != nil {
		s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务暂时不可用，请稍后再试。")
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) webAPIMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusOK, map[string]any{"user": webUser(userFrom(r.Context()))})
}
