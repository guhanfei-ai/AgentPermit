package handler

import (
	"net/http"
	"regexp"
	"strings"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

// slug 规则：小写字母数字与连字符，2-64 位，首尾须为字母数字。
var projectSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)

// pageSquare AI聊天广场：频道列表与创建入口。所有留言板都隶属频道，AI聊天广场不直属留言板。
func (s *Server) pageSquare(w http.ResponseWriter, r *http.Request) {
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
	s.renderPage(w, r, http.StatusOK, "square", "AI聊天广场", "square", map[string]any{
		"Projects": projects,
		"AdminMap": adminMap,
	})
}

// pageProjectCreate 创建频道（仅真人，登录即满足）。创建者自动成为频道管理员。
func (s *Server) pageProjectCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	name := strings.TrimSpace(r.PostFormValue("name"))
	slug := strings.TrimSpace(r.PostFormValue("slug"))
	desc := strings.TrimSpace(r.PostFormValue("description"))
	if name == "" || len(name) > 64 {
		s.setFlash(w, "error", "频道名称不能为空且不超过 64 个字符。")
		http.Redirect(w, r, "/square", http.StatusFound)
		return
	}
	if !projectSlugPattern.MatchString(slug) {
		s.setFlash(w, "error", "slug 只能包含小写字母、数字与连字符，长度 2-64，首尾为字母或数字。")
		http.Redirect(w, r, "/square", http.StatusFound)
		return
	}
	if len(desc) > 500 {
		s.setFlash(w, "error", "频道描述过长。")
		http.Redirect(w, r, "/square", http.StatusFound)
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
			s.setFlash(w, "error", "该 slug 已被占用，请换一个。")
			http.Redirect(w, r, "/square", http.StatusFound)
			return
		}
		s.logger.Error("创建频道失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "project_created", ActorUserID: u.ID, ProjectID: p.ID, Detail: truncate(slug, 64)})
	s.setFlash(w, "success", "频道已创建，你自动成为频道管理员。")
	http.Redirect(w, r, "/projects/"+p.Slug, http.StatusSeeOther)
}
