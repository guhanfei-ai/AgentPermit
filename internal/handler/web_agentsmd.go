package handler

import (
	"net/http"
	"strconv"
	"strings"

	"agentpermit/internal/model"
)

const maxDocBodyBytes = 100000 // AGENTS.md 草稿上限（字节）

// pageAgentsmdEdit AGENTS.md 编辑页（项目管理员）：草稿编辑 + 发布 + 版本历史 + latest 移动。
// 项目根页对外只展示 latest 发布版本；普通留言不能覆盖这份官方引导。
func (s *Server) pageAgentsmdEdit(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	doc, err := s.store.GetProjectDoc(r.Context(), p.ID)
	if err != nil {
		s.logger.Error("查询 AGENTS.md 失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	versions, err := s.store.ListDocVersions(r.Context(), p.ID)
	if err != nil {
		s.logger.Error("查询 AGENTS.md 版本失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.renderPage(w, r, http.StatusOK, "agentsmd", "AGENTS.md · "+p.Name, "project", map[string]any{
		"Project":  p,
		"Doc":      doc,
		"Versions": versions,
	})
}

// pageAgentsmdDraft 保存草稿（不改变对外生效的 latest 版本）。
func (s *Server) pageAgentsmdDraft(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	body := strings.TrimSpace(r.PostFormValue("body"))
	if len(body) > maxDocBodyBytes {
		s.setFlash(w, "error", "AGENTS.md 内容过长（上限 100000 字符）。")
		http.Redirect(w, r, "/projects/"+p.Slug+"/agents-md", http.StatusFound)
		return
	}
	if err := s.store.SaveDocDraft(r.Context(), p.ID, body, u.ID); err != nil {
		s.logger.Error("保存草稿失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.setFlash(w, "success", "草稿已保存（尚未发布，对外仍为 latest 版本）。")
	http.Redirect(w, r, "/projects/"+p.Slug+"/agents-md", http.StatusSeeOther)
}

// pageAgentsmdPublish 发布：把当前草稿快照为新的不可变版本，并把 latest 指向它。
func (s *Server) pageAgentsmdPublish(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	version, err := s.store.PublishDoc(r.Context(), p.ID, u.ID)
	if err != nil {
		s.logger.Error("发布 AGENTS.md 失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "agentsmd_published", ActorUserID: u.ID, ProjectID: p.ID, Detail: "v" + strconv.Itoa(version)})
	s.setFlash(w, "success", "已发布 v"+strconv.Itoa(version)+" 并将 latest 指向该版本。")
	http.Redirect(w, r, "/projects/"+p.Slug+"/agents-md", http.StatusSeeOther)
}

// pageAgentsmdSetLatest 移动 latest 标记到指定已发布版本（可回指旧版本实现回滚）。
func (s *Server) pageAgentsmdSetLatest(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p := s.getProject(w, r)
	if p == nil {
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要项目管理员权限。")
		return
	}
	version, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("version")))
	if err != nil {
		s.setFlash(w, "error", "版本号无效。")
		http.Redirect(w, r, "/projects/"+p.Slug+"/agents-md", http.StatusFound)
		return
	}
	if err := s.store.SetDocLatest(r.Context(), p.ID, version); err != nil {
		s.setFlash(w, "error", "版本不存在。")
		http.Redirect(w, r, "/projects/"+p.Slug+"/agents-md", http.StatusFound)
		return
	}
	s.audit(r, &model.AuditLog{Event: "agentsmd_latest_moved", ActorUserID: u.ID, ProjectID: p.ID, Detail: "v" + strconv.Itoa(version)})
	s.setFlash(w, "success", "latest 已指向 v"+strconv.Itoa(version)+"。")
	http.Redirect(w, r, "/projects/"+p.Slug+"/agents-md", http.StatusSeeOther)
}
