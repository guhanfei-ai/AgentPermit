package handler

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

var allowedMethods = map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true}

// validateCapabilityInput 校验并清洗能力表单字段，返回错误消息。
func validateCapabilityInput(name, slug, desc, endpointURL, method, apiPath, spec string, isEdit bool) string {
	if name == "" || len(name) > 100 {
		return "能力名称不能为空且不超过 100 个字符。"
	}
	if !isEdit && !slugPattern.MatchString(slug) {
		return "slug 仅允许小写字母、数字与连字符，长度 3-63，且以字母数字开头结尾。"
	}
	if len(desc) > 500 {
		return "描述过长。"
	}
	u, err := url.Parse(endpointURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "独立服务地址必须是合法的 http/https URL（如 http://127.0.0.1:9090）。"
	}
	if len(endpointURL) > 500 {
		return "独立服务地址过长。"
	}
	if !allowedMethods[method] {
		return "不支持的 HTTP 方法。"
	}
	if !strings.HasPrefix(apiPath, "/") || len(apiPath) > 200 || strings.ContainsAny(apiPath, " \t") {
		return "业务路径必须以 / 开头，且不含空格。"
	}
	if len(spec) > 20000 {
		return "能力内容过长。"
	}
	return ""
}

func (s *Server) pageCapabilities(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	caps, err := s.store.ListCapabilitiesByOwner(r.Context(), u.ID)
	if err != nil {
		s.logger.Error("查询能力失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "capabilities", "我的能力", "capabilities", map[string]any{"Capabilities": caps})
}

func (s *Server) pageCapabilityNew(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, http.StatusOK, "capability_form", "新建能力", "capabilities", map[string]any{
		"IsEdit":     false,
		"Capability": &model.Capability{HTTPMethod: "GET", AccessMode: model.AccessModeTeam},
	})
}

func (s *Server) pageCapabilityCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	slug := strings.ToLower(strings.TrimSpace(r.PostFormValue("slug")))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	endpointURL := strings.TrimSpace(r.PostFormValue("endpoint_url"))
	method := strings.ToUpper(strings.TrimSpace(r.PostFormValue("http_method")))
	apiPath := strings.TrimSpace(r.PostFormValue("api_path"))
	spec := r.PostFormValue("spec_markdown")
	mode := r.PostFormValue("access_mode")

	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/capabilities/new", http.StatusFound)
	}
	if msg := validateCapabilityInput(name, slug, desc, endpointURL, method, apiPath, spec, false); msg != "" {
		fail(msg)
		return
	}
	if mode != model.AccessModeTeam && mode != model.AccessModeAllowlist {
		fail("访问模式不合法。")
		return
	}

	svcToken, svcHash, svcHint := auth.NewToken(auth.ServiceTokenPrefix)
	capability := &model.Capability{
		ID:           store.NewID(),
		OwnerUserID:  u.ID,
		Name:         name,
		Slug:         slug,
		Description:  desc,
		EndpointURL:  endpointURL,
		HTTPMethod:   method,
		APIPath:      apiPath,
		SpecMarkdown: spec,
		AccessMode:   mode,
		Status:       model.StatusActive,
	}
	cred := &model.ServiceCredential{CapabilityID: capability.ID, TokenHash: svcHash, TokenHint: svcHint}
	if err := s.store.CreateCapability(r.Context(), capability, cred); err != nil {
		if err == store.ErrConflict {
			fail("slug 已被占用。")
			return
		}
		s.logger.Error("创建能力失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_created", ActorUserID: u.ID, CapabilityID: capability.ID, Detail: truncate(slug, 64)})
	s.setOnceSecret(w, "service_token", capability.ID, svcToken)
	http.Redirect(w, r, "/capabilities/"+capability.ID+"/service-token", http.StatusSeeOther)
}

// ownedCapability 加载能力并校验所有权，防止越权操作他人能力。
func (s *Server) ownedCapability(w http.ResponseWriter, r *http.Request, u *model.User) *model.Capability {
	id := r.PathValue("id")
	c, err := s.store.GetCapabilityByID(r.Context(), id)
	if err != nil || c.OwnerUserID != u.ID {
		// 不区分不存在与无权，避免泄露存在性
		s.renderError(w, r, http.StatusNotFound, "能力不存在。")
		return nil
	}
	return c
}

func (s *Server) pageCapabilityEdit(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	s.renderPage(w, r, http.StatusOK, "capability_form", "编辑能力", "capabilities", map[string]any{
		"IsEdit":     true,
		"Capability": c,
	})
}

func (s *Server) pageCapabilityUpdate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	endpointURL := strings.TrimSpace(r.PostFormValue("endpoint_url"))
	method := strings.ToUpper(strings.TrimSpace(r.PostFormValue("http_method")))
	apiPath := strings.TrimSpace(r.PostFormValue("api_path"))
	spec := r.PostFormValue("spec_markdown")
	mode := r.PostFormValue("access_mode")

	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, "/capabilities/"+c.ID+"/edit", http.StatusFound)
	}
	if msg := validateCapabilityInput(name, c.Slug, desc, endpointURL, method, apiPath, spec, true); msg != "" {
		fail(msg)
		return
	}
	if mode != model.AccessModeTeam && mode != model.AccessModeAllowlist {
		fail("访问模式不合法。")
		return
	}
	c.Name, c.Description, c.EndpointURL, c.HTTPMethod, c.APIPath, c.SpecMarkdown, c.AccessMode =
		name, desc, endpointURL, method, apiPath, spec, mode
	if err := s.store.UpdateCapability(r.Context(), c.ID, u.ID, c); err != nil {
		s.logger.Error("更新能力失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_updated", ActorUserID: u.ID, CapabilityID: c.ID})
	s.setFlash(w, "success", "能力已更新。")
	http.Redirect(w, r, "/capabilities", http.StatusFound)
}

func (s *Server) pageCapabilityEnable(w http.ResponseWriter, r *http.Request) {
	s.setCapabilityStatus(w, r, model.StatusActive, "capability_enabled", "能力已启用。")
}

func (s *Server) pageCapabilityDisable(w http.ResponseWriter, r *http.Request) {
	s.setCapabilityStatus(w, r, model.StatusDisabled, "capability_disabled", "能力已停用，所有 Agent（包括你自己的）将无法发现或调用。")
}

func (s *Server) setCapabilityStatus(w http.ResponseWriter, r *http.Request, status, event, msg string) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	if err := s.store.SetCapabilityStatus(r.Context(), c.ID, u.ID, status); err != nil {
		s.logger.Error("更新能力状态失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: event, ActorUserID: u.ID, CapabilityID: c.ID})
	s.setFlash(w, "success", msg)
	http.Redirect(w, r, "/capabilities", http.StatusFound)
}
