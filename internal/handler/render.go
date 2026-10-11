package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"agentpermit/internal/model"
)

// Cookie 名称。ap_ 为 AgentPermit 规范前缀；
// legacyCookieSession 为更名前的会话 Cookie，读取时回退，避免已有登录态丢失。
const (
	cookieSession       = "ap_session"
	legacyCookieSession = "aad_session"
	cookieCSRF          = "ap_csrf"
	cookieFlash         = "ap_flash"
	cookieOnce          = "ap_once"
	legacyCookieCSRF    = "aad_csrf"
)

// Flash 是跨重定向的一次性提示消息。
type Flash struct {
	Kind string `json:"kind"` // success / error
	Text string `json:"text"`
}

// PageData 是所有页面模板的根数据。
type PageData struct {
	Title     string
	Page      string // 导航高亮 key
	User      *model.User
	CSRFToken string
	Flash     *Flash
	Data      any
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// renderPage 渲染页面：从 ctx 取当前用户与 CSRF Token，弹出 Flash。
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, status int, page, title, pageKey string, data any) {
	u := userFrom(r.Context())
	csrf := s.csrfTokenFor(r, u)
	pd := PageData{Title: title, Page: pageKey, User: u, CSRFToken: csrf, Flash: popFlash(w, r), Data: data}
	t, ok := s.tmpl[page]
	if !ok {
		s.logger.Error("模板不存在", "page", page)
		http.Error(w, "内部错误", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base", pd); err != nil {
		// 半写出状态只记录日志
		s.logger.Error("渲染模板失败", "page", page, "err", err)
	}
}

// renderError 渲染通用错误页。
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.renderPage(w, r, status, "error", "错误", "", map[string]any{"Message": msg})
}

// ---- Flash cookie ----

func (s *Server) setFlash(w http.ResponseWriter, kind, text string) {
	b, _ := json.Marshal(Flash{Kind: kind, Text: text})
	s.setCookie(w, cookieFlash, base64.RawURLEncoding.EncodeToString(b), 30)
}

func popFlash(w http.ResponseWriter, r *http.Request) *Flash {
	c, err := r.Cookie(cookieFlash)
	if err != nil || c.Value == "" {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: cookieFlash, Value: "", Path: "/", MaxAge: -1})
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	var f Flash
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return &f
}

// ---- 一次性凭证 Cookie ----
// 原始凭证只通过短期 HttpOnly Cookie 从 POST 跳转带到展示页，
// 展示后立即清除；刷新展示页无法再次取回，也不进入 URL 与长期 Session。

type onceSecret struct {
	Kind  string `json:"kind"`   // agent_token / service_token
	RefID string `json:"ref_id"` // agent id 或 capability id
	Token string `json:"token"`
}

func (s *Server) setOnceSecret(w http.ResponseWriter, kind, refID, token string) {
	b, _ := json.Marshal(onceSecret{Kind: kind, RefID: refID, Token: token})
	s.setCookie(w, cookieOnce, base64.RawURLEncoding.EncodeToString(b), 120)
}

// popOnceSecret 读取并清除一次性凭证，kind 与 refID 必须匹配。
func (s *Server) popOnceSecret(w http.ResponseWriter, r *http.Request, kind, refID string) (string, bool) {
	c, err := r.Cookie(cookieOnce)
	// 立即失效，无论是否匹配
	http.SetCookie(w, &http.Cookie{Name: cookieOnce, Value: "", Path: "/", MaxAge: -1})
	if err != nil || c.Value == "" {
		return "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", false
	}
	var sec onceSecret
	if json.Unmarshal(b, &sec) != nil || sec.Kind != kind || sec.RefID != refID {
		return "", false
	}
	return sec.Token, true
}

// ---- JSON 响应 ----

type jsonErrorBody struct {
	Error     jsonErrorDetail `json:"error"`
	RequestID string          `json:"request_id"`
}

type jsonErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (s *Server) jsonError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, r, status, jsonErrorBody{
		Error:     jsonErrorDetail{Code: code, Message: message},
		RequestID: requestIDFrom(r.Context()),
	})
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(w, `{"error":{"code":"internal","message":"编码失败"},"request_id":%q}`, requestIDFrom(r.Context()))
	}
}

// ---- 审计 ----

// audit 记录审计事件。detail 只允许脱敏字段（用户名、slug 等），禁止凭证原文。
func (s *Server) audit(r *http.Request, e *model.AuditLog) {
	e.RequestID = requestIDFrom(r.Context())
	if e.Outcome == "" {
		e.Outcome = "success"
	}
	if err := s.store.InsertAudit(r.Context(), e); err != nil {
		// 审计失败不阻断主流程，但要留痕
		s.logger.Error("写入审计失败", "event", e.Event, "err", err, "request_id", e.RequestID)
	}
}
