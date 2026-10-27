package handler

import (
	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) pageServers(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	all, err := s.store.ListTrustedServers(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	filtered := []*model.TrustedServer{}
	for _, v := range all {
		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		if q != "" && !strings.Contains(strings.ToLower(v.Name+" "+v.ID+" "+v.Description), q) {
			continue
		}
		if env := r.URL.Query().Get("environment"); env != "" && v.Environment != env {
			continue
		}
		filtered = append(filtered, v)
	}
	users := []*model.User{}
	if u.IsAdmin() {
		users, err = s.store.ListUsers(r.Context())
		if err != nil {
			s.trustFailure(w, r, err)
			return
		}
	}
	s.renderPage(w, r, 200, "servers", "Server端接入", "servers", map[string]any{"Servers": paginateTrust(r, "page", filtered), "Users": users, "Query": r.URL.Query().Get("q"), "Environment": r.URL.Query().Get("environment"), "Kinds": serverKinds(), "Server": &model.TrustedServer{Kind: "Server", Status: "active", OwnerUserID: u.ID}})
}

func (s *Server) pageServerDetail(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	v, err := s.store.GetTrustedServer(r.Context(), r.PathValue("id"))
	if err != nil {
		s.trustFailure(w, r, store.ErrNotFound)
		return
	}
	groups, err := s.store.ListFieldGroups(r.Context(), v.ID)
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	owner := ""
	if !u.IsAdmin() {
		owner = u.ID
	}
	grants, err := s.store.ListTemporaryGrants(r.Context(), owner)
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	related := []*model.TemporaryGrant{}
	for _, g := range grants {
		if g.ServerID == v.ID {
			related = append(related, g)
		}
	}
	users := []*model.User{}
	if u.IsAdmin() {
		users, err = s.store.ListUsers(r.Context())
		if err != nil {
			s.trustFailure(w, r, err)
			return
		}
	}
	s.renderPage(w, r, 200, "server_detail", v.Name, "servers", map[string]any{"Server": v, "Users": users, "Grants": paginateTrust(r, "page", related), "Kinds": serverKinds(), "FieldGroups": groups})
}

func parseOrigin(raw string) (string, error) {
	v, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || v.Hostname() == "" || (v.Scheme != "https" && v.Scheme != "http") || v.User != nil || v.RawQuery != "" || v.Fragment != "" || (v.Path != "" && v.Path != "/") {
		return "", store.ErrInvalidTrust
	}
	return strings.ToLower(v.Scheme + "://" + v.Host), nil
}

func (s *Server) pageServerSave(w http.ResponseWriter, r *http.Request) {
	v := &model.TrustedServer{ID: r.PathValue("id"), Name: strings.TrimSpace(r.PostFormValue("name")), Kind: r.PostFormValue("kind"), Description: strings.TrimSpace(r.PostFormValue("description")), Environment: strings.TrimSpace(r.PostFormValue("environment")), OwnerUserID: r.PostFormValue("owner_user_id"), Status: r.PostFormValue("status")}
	origin, err := parseOrigin(r.PostFormValue("origin"))
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	v.Origin = origin
	owner, err := s.store.GetUserByID(r.Context(), v.OwnerUserID)
	if err != nil || !owner.IsActive() || v.Name == "" || len(v.Name) > 128 || len(v.Description) > 1000 || v.Environment == "" || len(v.Environment) > 64 || len(origin) > 500 || (v.Status != "active" && v.Status != "disabled") || (v.Kind != "MCP" && v.Kind != "Server" && v.Kind != "Nginx" && v.Kind != "其他") {
		s.trustFailure(w, r, store.ErrInvalidTrust)
		return
	}
	create := v.ID == ""
	secret := ""
	if create {
		v.ID = store.NewID()
		secret, v.TokenHash, v.TokenHint = auth.NewToken(serviceTokenPrefix)
	}
	if err := s.store.SaveTrustedServer(r.Context(), v, create); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "server_saved", ActorUserID: userFrom(r.Context()).ID, Detail: "server_id=" + v.ID})
	if create {
		s.showTrustSecret(w, r, "Server接入凭证", secret, "/servers/"+v.ID)
		return
	}
	s.trustRedirect(w, r, "/servers/"+v.ID, "Server信息已更新。")
}

func (s *Server) showTrustSecret(w http.ResponseWriter, r *http.Request, title, secret, back string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.renderPage(w, r, 200, "trust_secret", title, "trust", map[string]any{"Title": title, "Secret": secret, "Back": back})
}

func (s *Server) pageServerRotate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	token, hash, hint := auth.NewToken(serviceTokenPrefix)
	if err := s.store.RotateServerKey(r.Context(), id, hash, hint); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "server_key_rotated", ActorUserID: userFrom(r.Context()).ID, Detail: "server_id=" + id})
	s.showTrustSecret(w, r, "Server接入凭证", token, "/servers/"+id)
}

// pageFieldGroupCreate 在服务登记下登记能力契约变量编组。
// 一个Server可挂多个编组；定义由维护者预设，仅约束申报值的类型与取值，
// 不构成业务审批。v1 仅支持新增；已签发凭证保存定义快照，不受后续影响。
func (s *Server) pageFieldGroupCreate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f := &model.FieldGroup{ID: store.NewID(), ServerID: id, Name: r.PostFormValue("name"), Description: r.PostFormValue("description"), Definition: r.PostFormValue("definition"), CreatedBy: userFrom(r.Context()).ID}
	if err := s.store.SaveFieldGroup(r.Context(), f); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "field_group_created", ActorUserID: f.CreatedBy, Detail: "server_id=" + id + " group_id=" + f.ID})
	s.trustRedirect(w, r, "/servers/"+id, "变量编组已登记。")
}
