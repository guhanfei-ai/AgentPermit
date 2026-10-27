package handler

import (
	"net/http"
	"strings"
)

// registerAgentAPI 注册同一套 Agent 接口；mePath 保留旧身份查询路径的兼容差异。
func (s *Server) registerAgentAPI(mux *http.ServeMux, prefix, mePath string) {
	mux.HandleFunc("GET "+mePath, s.apiCredentialMe)
	mux.HandleFunc("GET "+prefix+"/capabilities", s.apiCapabilities)
	mux.HandleFunc("GET "+prefix+"/capabilities/{id}", s.apiCapabilityDetail)
	mux.HandleFunc("GET "+prefix+"/trusted-services", s.apiTrustedServers)
	mux.HandleFunc("POST "+prefix+"/temporary-credentials", s.apiGrantCreate)
	// 频道和帖子只读，发言可追加为新楼；创建与管理仍由真人入口负责。
	mux.HandleFunc("GET "+prefix+"/projects", s.apiProjects)
	mux.HandleFunc("GET "+prefix+"/projects/{id}", s.apiProjectDetail)
	mux.HandleFunc("GET "+prefix+"/projects/{id}/threads", s.apiProjectThreads)
	mux.HandleFunc("GET "+prefix+"/threads/{id}", s.apiThreadDetail)
	mux.HandleFunc("POST "+prefix+"/threads/{id}/floors", s.apiThreadAppend)
}

func (s *Server) registerWebAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /web/v1/csrf", s.webAPICSRF)
	mux.HandleFunc("POST /web/v1/auth/login", s.csrfProtectJSON(s.webAPILogin))
	mux.HandleFunc("POST /web/v1/auth/logout", s.requireWebAPI(s.csrfProtectJSON(s.webAPILogout)))
	mux.HandleFunc("GET /web/v1/me", s.requireWebAPI(s.webAPIMe))
}

// jsonAPIRouter 将路由未命中与方法不允许也转为统一 JSON 错误。
// 仍通过 ServeHTTP 分派匹配请求，由标准路由器设置 PathValue。
func (s *Server) jsonAPIRouter(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
		var allowed []string
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions} {
			probe := r.Clone(r.Context())
			probe.Method = method
			if _, pattern := mux.Handler(probe); pattern != "" {
				allowed = append(allowed, method)
			}
		}
		if len(allowed) > 0 {
			w.Header().Set("Allow", strings.Join(allowed, ", "))
			s.jsonError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "该接口不支持此请求方法")
			return
		}
		s.jsonError(w, r, http.StatusNotFound, "not_found", "接口不存在")
	})
}
