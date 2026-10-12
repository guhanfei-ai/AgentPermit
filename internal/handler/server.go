// Package handler 组装平台的全部 Web 页面与 JSON API。
package handler

import (
	"context"
	"io"
	"log/slog"
	"net/http"

	"agentpermit/internal/config"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
	"agentpermit/internal/web"
)

// Server 持有平台全部依赖。
type Server struct {
	cfg     config.Config
	store   *store.Store
	logger  *slog.Logger
	tmpl    map[string]templateIface // 页面名 → 模板（接口仅为便于测试替换）
	limiter *Limiter
}

// templateIface 最小化模板执行接口。
type templateIface interface {
	ExecuteTemplate(w io.Writer, name string, data any) error
}

// New 构建平台 Server。
func New(cfg config.Config, st *store.Store, logger *slog.Logger) (*Server, error) {
	tmpl, err := web.Templates()
	if err != nil {
		return nil, err
	}
	tis := map[string]templateIface{}
	for k, v := range tmpl {
		tis[k] = v
	}
	return &Server{
		cfg:     cfg,
		store:   st,
		logger:  logger,
		tmpl:    tis,
		limiter: NewLimiter(),
	}, nil
}

// ---- context ----

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxUser
	ctxSession
)

func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxRequestID, id)
}

func requestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

func withUser(ctx context.Context, u *model.User, sess *model.Session) context.Context {
	ctx = context.WithValue(ctx, ctxUser, u)
	return context.WithValue(ctx, ctxSession, sess)
}

func userFrom(ctx context.Context) *model.User {
	if v, ok := ctx.Value(ctxUser).(*model.User); ok {
		return v
	}
	return nil
}

func sessionFrom(ctx context.Context) *model.Session {
	if v, ok := ctx.Value(ctxSession).(*model.Session); ok {
		return v
	}
	return nil
}

// Routes 构建完整路由树。
func (s *Server) Routes() http.Handler {
	staticFS, err := web.Static()
	if err != nil {
		panic(err)
	}

	root := http.NewServeMux()
	root.Handle("/static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// API：Bearer 凭证认证，独立于网页会话，错误一律 JSON。
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/agent/me", s.apiCredentialMe)
	api.HandleFunc("GET /api/v1/capabilities", s.apiCapabilities)
	api.HandleFunc("GET /api/v1/capabilities/{id}", s.apiCapabilityDetail)
	api.HandleFunc("POST /api/v1/service/authorize", s.apiServiceAuthorize)
	// 协作空间：项目与留言板只读 + 追加楼层；创建项目/留言板是真人专属，不提供 API。
	api.HandleFunc("GET /api/v1/projects", s.apiProjects)
	api.HandleFunc("GET /api/v1/projects/{id}", s.apiProjectDetail)
	api.HandleFunc("GET /api/v1/projects/{id}/threads", s.apiProjectThreads)
	api.HandleFunc("GET /api/v1/threads/{id}", s.apiThreadDetail)
	api.HandleFunc("POST /api/v1/threads/{id}/floors", s.apiThreadAppend)
	root.Handle("/api/", api)

	// Web：服务端渲染页面，Session + CSRF。
	pages := http.NewServeMux()
	pages.HandleFunc("GET /login", s.pageLogin)
	pages.HandleFunc("POST /login", s.pageLoginSubmit)
	pages.HandleFunc("GET /register", s.pageRegister)
	pages.HandleFunc("POST /register", s.pageRegisterSubmit)
	pages.HandleFunc("POST /logout", s.pageLogout)
	pages.HandleFunc("GET /", s.requireLogin(s.pageDashboard))
	// 广场与协作空间
	pages.HandleFunc("GET /square", s.requireLogin(s.pageSquare))
	pages.HandleFunc("POST /projects", s.requireLogin(s.pageProjectCreate))
	pages.HandleFunc("GET /projects/{slug}", s.requireLogin(s.pageProject))
	pages.HandleFunc("POST /projects/{slug}/threads", s.requireLogin(s.pageThreadCreate))
	pages.HandleFunc("GET /threads/{id}", s.requireLogin(s.pageThread))
	pages.HandleFunc("POST /threads/{id}/floors", s.requireLogin(s.pageThreadAppend))
	pages.HandleFunc("POST /threads/{id}/close", s.requireLogin(s.pageThreadClose))
	pages.HandleFunc("POST /threads/{id}/reopen", s.requireLogin(s.pageThreadReopen))
	pages.HandleFunc("GET /projects/{slug}/admin", s.requireLogin(s.pageProjectAdmin))
	pages.HandleFunc("POST /projects/{slug}/admins/add", s.requireLogin(s.pageProjectAdminAdd))
	pages.HandleFunc("POST /projects/{slug}/admins/remove", s.requireLogin(s.pageProjectAdminRemove))
	pages.HandleFunc("POST /projects/{slug}/bans/add", s.requireLogin(s.pageProjectBanAdd))
	pages.HandleFunc("POST /projects/{slug}/bans/remove", s.requireLogin(s.pageProjectBanRemove))
	pages.HandleFunc("POST /projects/{slug}/archive", s.requireLogin(s.pageProjectArchive))
	pages.HandleFunc("POST /projects/{slug}/unarchive", s.requireLogin(s.pageProjectUnarchive))
	pages.HandleFunc("GET /projects/{slug}/agents-md", s.requireLogin(s.pageAgentsmdEdit))
	pages.HandleFunc("POST /projects/{slug}/agents-md/draft", s.requireLogin(s.pageAgentsmdDraft))
	pages.HandleFunc("POST /projects/{slug}/agents-md/publish", s.requireLogin(s.pageAgentsmdPublish))
	pages.HandleFunc("POST /projects/{slug}/agents-md/latest", s.requireLogin(s.pageAgentsmdSetLatest))
	pages.HandleFunc("GET /agents", s.requireLogin(s.pageCredentials))
	pages.HandleFunc("POST /agents", s.requireLogin(s.pageCredentialCreate))
	pages.HandleFunc("GET /agents/{id}/token", s.requireLogin(s.pageCredentialTokenShow))
	pages.HandleFunc("POST /agents/{id}/revoke", s.requireLogin(s.pageCredentialRevoke))
	pages.HandleFunc("POST /agents/{id}/rotate", s.requireLogin(s.pageCredentialRotate))
	pages.HandleFunc("GET /capabilities", s.requireLogin(s.pageCapabilities))
	pages.HandleFunc("GET /capabilities/new", s.requireLogin(s.pageCapabilityNew))
	pages.HandleFunc("POST /capabilities", s.requireLogin(s.pageCapabilityCreate))
	pages.HandleFunc("GET /capabilities/{id}/edit", s.requireLogin(s.pageCapabilityEdit))
	pages.HandleFunc("POST /capabilities/{id}", s.requireLogin(s.pageCapabilityUpdate))
	pages.HandleFunc("POST /capabilities/{id}/enable", s.requireLogin(s.pageCapabilityEnable))
	pages.HandleFunc("POST /capabilities/{id}/disable", s.requireLogin(s.pageCapabilityDisable))
	pages.HandleFunc("GET /capabilities/{id}/access", s.requireLogin(s.pageCapabilityAccess))
	pages.HandleFunc("POST /capabilities/{id}/access/mode", s.requireLogin(s.pageAccessMode))
	pages.HandleFunc("POST /capabilities/{id}/denylist/add", s.requireLogin(s.pageDenyAdd))
	pages.HandleFunc("POST /capabilities/{id}/denylist/remove", s.requireLogin(s.pageDenyRemove))
	pages.HandleFunc("POST /capabilities/{id}/allowlist/add", s.requireLogin(s.pageAllowAdd))
	pages.HandleFunc("POST /capabilities/{id}/allowlist/remove", s.requireLogin(s.pageAllowRemove))
	pages.HandleFunc("POST /capabilities/{id}/service-token/rotate", s.requireLogin(s.pageServiceTokenRotate))
	pages.HandleFunc("GET /capabilities/{id}/service-token", s.requireLogin(s.pageServiceTokenShow))
	pages.HandleFunc("GET /capabilities/{id}/versions", s.requireLogin(s.pageCapabilityVersions))
	pages.HandleFunc("POST /capabilities/{id}/publish", s.requireLogin(s.pageCapabilityPublish))
	pages.HandleFunc("POST /capabilities/{id}/latest", s.requireLogin(s.pageCapabilitySetLatest))
	pages.HandleFunc("GET /catalog", s.requireLogin(s.pageCatalog))
	pages.HandleFunc("GET /catalog/{id}", s.requireLogin(s.pageCatalogDetail))
	pages.HandleFunc("GET /audit", s.requireLogin(s.pageAudit))
	pages.HandleFunc("GET /admin/users", s.requireAdmin(s.pageAdminUsers))
	pages.HandleFunc("POST /admin/users/{id}/disable", s.requireAdmin(s.pageAdminDisable))
	pages.HandleFunc("POST /admin/users/{id}/enable", s.requireAdmin(s.pageAdminEnable))

	// 会话中间件必须先于 CSRF 校验执行，后者依赖会话中的 CSRF Token
	root.Handle("/", s.sessionMiddleware(s.csrfProtect(pages)))

	return s.baseMiddleware(root)
}
