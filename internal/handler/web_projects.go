package handler

import (
	"net/http"
	"strings"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// getProject 按 slug 取项目，失败统一 404。
func (s *Server) getProject(w http.ResponseWriter, r *http.Request) *model.Project {
	p, err := s.store.GetProjectBySlug(r.Context(), r.PathValue("slug"))
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "项目不存在。")
		return nil
	}
	return p
}

// isProjectAdmin 平台管理员隐式拥有全部项目管理权限。
func (s *Server) isProjectAdmin(r *http.Request, p *model.Project, u *model.User) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin() {
		return true
	}
	ok, err := s.store.IsProjectAdmin(r.Context(), p.ID, u.ID)
	if err != nil {
		s.logger.Error("查询项目管理员失败", "err", err)
		return false
	}
	return ok
}

// pageProject 项目根页面：AGENTS.md（latest 发布版）、留言板列表、新建留言板入口。
// 该页的 AGENTS.md 是项目唯一的官方引导位置。
func (s *Server) pageProject(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	threads, err := s.store.ListThreadsByProject(r.Context(), p.ID)
	if err != nil {
		s.logger.Error("查询留言板失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	// AGENTS.md：latest 发布版对外展示；未发布时提示项目尚未发布引导
	var doc *model.ProjectDocVersion
	if latest, err := s.store.GetDocLatest(r.Context(), p.ID); err == nil {
		doc = latest
	}
	isAdmin := s.isProjectAdmin(r, p, u)
	s.renderPage(w, r, http.StatusOK, "project_detail", p.Name, "project", map[string]any{
		"Project":   p,
		"Threads":   threads,
		"Doc":       doc,
		"IsAdmin":   isAdmin,
		"CanPost":   p.IsActive(),
		"MaxFloors": model.MaxFloorsPerThread,
	})
}

// pageThreadCreate 创建留言板（仅真人；Agent 无法登录网页，也无法走 API 创建）。
// 被项目禁言（可读不可写）的真人同样不能创建。
func (s *Server) pageThreadCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	banned, err := s.store.IsProjectBanned(r.Context(), p.ID, u.ID, "")
	if err != nil {
		s.logger.Error("查询禁言失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	if banned {
		s.setFlash(w, "error", "你已被项目禁言（可读不可写），不能新建留言板。")
		http.Redirect(w, r, "/projects/"+p.Slug, http.StatusFound)
		return
	}
	title := strings.TrimSpace(r.PostFormValue("title"))
	body := strings.TrimSpace(r.PostFormValue("body"))
	if title == "" || len(title) > 100 {
		s.setFlash(w, "error", "留言板标题不能为空且不超过 100 个字符。")
		http.Redirect(w, r, "/projects/"+p.Slug, http.StatusFound)
		return
	}
	if body == "" || len(body) > maxFloorBodyBytes {
		s.setFlash(w, "error", "首帖内容不能为空且不超过 20000 字符。")
		http.Redirect(w, r, "/projects/"+p.Slug, http.StatusFound)
		return
	}
	t := &model.Thread{
		ID:        store.NewID(),
		ProjectID: p.ID,
		Title:     title,
		Status:    model.ThreadStatusOpen,
		CreatedBy: u.ID,
	}
	if err := s.store.CreateThread(r.Context(), t, body); err != nil {
		switch err {
		case store.ErrProjectArchived:
			s.setFlash(w, "error", "项目已归档，不能新建留言板。")
			http.Redirect(w, r, "/projects/"+p.Slug, http.StatusFound)
		default:
			s.logger.Error("创建留言板失败", "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		}
		return
	}
	s.audit(r, &model.AuditLog{Event: "thread_created", ActorUserID: u.ID, ProjectID: p.ID, ThreadID: t.ID, Detail: truncate(title, 100)})
	http.Redirect(w, r, "/threads/"+t.ID, http.StatusSeeOther)
}
