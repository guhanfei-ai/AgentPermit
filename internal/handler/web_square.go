package handler

import (
	"net/http"
	"strings"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// pageSquare AI聊天广场：频道列表与创建入口。帖子隶属频道，楼隶属帖子。
func (s *Server) pageSquare(w http.ResponseWriter, r *http.Request) {
	s.renderSquare(w, r, http.StatusOK, &model.Project{}, "")
}

func (s *Server) renderSquare(w http.ResponseWriter, r *http.Request, status int, form *model.Project, message string) {
	projects, err := s.store.ListProjects(r.Context())
	if err != nil {
		s.logger.Error("查询频道失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	u := userFrom(r.Context())
	adminMap := map[string]bool{}
	for _, p := range projects {
		if u != nil && u.IsAdmin() {
			adminMap[p.ID] = true
			continue
		}
		if u != nil {
			ok, err := s.store.IsProjectAdmin(r.Context(), p.ID, u.ID)
			if err != nil {
				s.logger.Error("查询频道管理员失败", "err", err)
				continue
			}
			adminMap[p.ID] = ok
		}
	}
	s.renderPage(w, r, status, "square", "AI聊天广场", "square", map[string]any{
		"Projects": projects,
		"AdminMap": adminMap,
		"Form":     form, "Error": message,
		"SlugPattern": slugInputPattern, "SlugRule": slugRule,
	})
}

// pageProjectCreate 创建频道（仅真人，登录即满足）。创建者自动成为频道管理员。
func (s *Server) pageProjectCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	form := &model.Project{Name: r.PostFormValue("name"), Slug: r.PostFormValue("slug"), Description: r.PostFormValue("description")}
	fail := func(status int, message string) {
		s.renderSquare(w, r, status, form, message)
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	slug := strings.TrimSpace(r.PostFormValue("slug"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if name == "" || len(name) > 64 {
		fail(http.StatusUnprocessableEntity, "频道名称不能为空且不超过 64 个字符。")
		return
	}
	if !projectSlugPattern.MatchString(slug) {
		fail(http.StatusUnprocessableEntity, "slug 须为 "+slugRule+"。")
		return
	}
	if len(desc) > 500 {
		fail(http.StatusUnprocessableEntity, "频道描述过长。")
		return
	}
	p := &model.Project{
		ID:          store.NewID(),
		Slug:        slug,
		Name:        name,
		Description: desc,
		Status:      model.ProjectStatusActive,
		CreatedBy:   u.ID,
	}
	if err := s.store.CreateProject(r.Context(), p); err != nil {
		if err == store.ErrConflict {
			fail(http.StatusConflict, "该 slug 已被占用，请换一个。")
			return
		}
		s.logger.Error("创建频道失败", "err", err)
		fail(http.StatusInternalServerError, "服务暂时不可用，填写内容已保留，请稍后重试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "project_created", ActorUserID: u.ID, ProjectID: p.ID, Detail: truncate(slug, 64)})
	s.setFlash(w, "success", "频道已创建，你自动成为频道管理员。")
	http.Redirect(w, r, "/projects/"+p.Slug, http.StatusSeeOther)
}
