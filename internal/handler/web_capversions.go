package handler

import (
	"net/http"
	"strconv"
	"strings"

	"agentpermit/internal/model"
)

// pageCapabilityVersions 版本管理页（能力所有者）：
// 版本历史、latest 标记位置、发布当前草稿、把 latest 回指旧版本。
func (s *Server) pageCapabilityVersions(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	versions, err := s.store.ListCapabilityVersions(r.Context(), c.ID)
	if err != nil {
		s.logger.Error("查询能力版本失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	latest, err := s.store.GetCapabilityLatestSnapshot(r.Context(), c.ID)
	draftDirty := false
	if err == nil && latest != nil {
		draftDirty = latest.Name != c.Name || latest.Description != c.Description ||
			latest.EndpointURL != c.EndpointURL || latest.HTTPMethod != c.HTTPMethod ||
			latest.APIPath != c.APIPath || latest.SpecMarkdown != c.SpecMarkdown
	}
	s.renderPage(w, r, http.StatusOK, "capability_versions", "能力版本 · "+c.Name, "capabilities", map[string]any{
		"Capability": c,
		"Versions":   versions,
		"DraftDirty": draftDirty,
	})
}

// pageCapabilityPublish 发布：把当前草稿（可编辑字段）快照为新的不可变版本，
// 并把 latest 指向它。发布后 Agent 立即可见。
func (s *Server) pageCapabilityPublish(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	v, err := s.store.PublishCapability(r.Context(), c.ID)
	if err != nil {
		s.logger.Error("发布能力版本失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_version_published", ActorUserID: u.ID, CapabilityID: c.ID, Detail: "v" + strconv.Itoa(v.Version)})
	s.setFlash(w, "success", "已发布 v"+strconv.Itoa(v.Version)+" 并将 latest 指向该版本。")
	http.Redirect(w, r, "/capabilities/"+c.ID+"/versions", http.StatusSeeOther)
}

// pageCapabilitySetLatest 把 latest 标记移动到指定已发布版本（可回指旧版本实现回滚）。
// 注意：内容回滚不影响实时访问控制（黑白名单、启停状态）。
func (s *Server) pageCapabilitySetLatest(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	c := s.ownedCapability(w, r, u)
	if c == nil {
		return
	}
	version, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("version")))
	if err != nil {
		s.setFlash(w, "error", "版本号无效。")
		http.Redirect(w, r, "/capabilities/"+c.ID+"/versions", http.StatusFound)
		return
	}
	if err := s.store.SetCapabilityLatest(r.Context(), c.ID, version); err != nil {
		s.setFlash(w, "error", "版本不存在。")
		http.Redirect(w, r, "/capabilities/"+c.ID+"/versions", http.StatusFound)
		return
	}
	s.audit(r, &model.AuditLog{Event: "capability_latest_moved", ActorUserID: u.ID, CapabilityID: c.ID, Detail: "v" + strconv.Itoa(version)})
	s.setFlash(w, "success", "latest 已指向 v"+strconv.Itoa(version)+"。访问控制不受影响。")
	http.Redirect(w, r, "/capabilities/"+c.ID+"/versions", http.StatusSeeOther)
}
