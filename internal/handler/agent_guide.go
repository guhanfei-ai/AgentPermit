package handler

import (
	"agentpermit/internal/web"
	"bytes"
	"html/template"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

var agentGuideMarkdown = goldmark.New(goldmark.WithExtensions(extension.GFM))

type agentGuidePageData struct {
	Content     template.HTML
	Environment string
}

// serveAgentGuide 按请求读取接入说明，编辑文件后无需重启服务。
// 说明不含账号数据或凭证，允许匿名读取；业务接口仍独立校验 Agent Token。
func (s *Server) serveAgentGuide(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Add("Vary", "Accept")
	body := web.AgentGuide
	if s.cfg.ServerAgentsPath != "" {
		var err error
		body, err = os.ReadFile(s.cfg.ServerAgentsPath)
		if err != nil {
			s.logger.Error("读取 Agent 接入说明失败", "err", err)
			http.Error(w, "Agent 接入说明暂不可用，请联系管理员检查说明文件。", http.StatusServiceUnavailable)
			return
		}
	}
	// 说明文件保留默认变量名，响应统一适配本实例的客户端前缀；
	// 额外使用规范地址未配置时明确提示待配置，不编造任何占位地址。
	specURL := s.cfg.UsageGuideURL
	if specURL == "" {
		specURL = "未配置额外使用规范，请以本接入说明及服务提供者的说明为准。"
	}
	body = []byte(strings.NewReplacer(
		"AGENTPERMIT_BASE_URL", s.cfg.ClientEnvName("BASE_URL"),
		"AGENTPERMIT_AGENT_TOKEN", s.cfg.ClientEnvName("AGENT_TOKEN"),
		"AGENTPERMIT_USAGE_GUIDE_URL", specURL,
	).Replace(string(body)))
	if agentGuideWantsHTML(r) {
		var rendered bytes.Buffer
		err := agentGuideMarkdown.Convert(body, &rendered)
		if err != nil {
			s.logger.Error("渲染 Agent 接入说明失败", "err", err)
			http.Error(w, "Agent 接入说明暂不可用。", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		// 仅浏览器页面解析会话并复用公共布局；原文分支不携带导航、脚本或会话内容。
		env := s.cfg.Environment
		if env == "" {
			env = "默认"
		}
		s.sessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.renderPage(w, r, http.StatusOK, "agent_guide", "AI README", "agent-guide", agentGuidePageData{
				// 仅信任默认安全模式渲染的 Markdown，不允许原始 HTML 或脚本。
				Content:     template.HTML(rendered.String()),
				Environment: env,
			})
		})).ServeHTTP(w, r)
		return
	}
	// 未明确请求 HTML 时返回适配变量名后的 Markdown，保持命令行和 Agent 的读取行为。
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(body)
}

// agentGuideWantsHTML 仅在显式接受 HTML 且未更偏好原文时渲染，不猜测 User-Agent。
func agentGuideWantsHTML(r *http.Request) bool {
	var htmlQuality, rawQuality float64
	for _, accept := range r.Header.Values("Accept") {
		for _, item := range strings.Split(accept, ",") {
			mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(item))
			if err != nil {
				continue
			}
			quality := 1.0
			if value, ok := params["q"]; ok {
				quality, err = strconv.ParseFloat(value, 64)
				if err != nil || !(quality > 0 && quality <= 1) {
					continue
				}
			}
			switch mediaType {
			case "text/html":
				htmlQuality = max(htmlQuality, quality)
			case "text/plain", "text/markdown", "text/*", "*/*":
				rawQuality = max(rawQuality, quality)
			}
		}
	}
	return htmlQuality > 0 && htmlQuality >= rawQuality
}
