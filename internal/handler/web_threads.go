package handler

import (
	"net/http"
	"strconv"
	"strings"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

const maxFloorBodyBytes = 20000 // 单层楼内容上限（字节）

// webFloorsPageSize 网页端默认展示最近 100 楼，更早的通过 ?after= 分段查看。
const webFloorsPageSize = 100

// pageThread 帖子页：楼层列表 + 真人追加表单 + 管理员关闭/重开。
func (s *Server) pageThread(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	t, err := s.store.GetThreadByID(r.Context(), r.PathValue("id"))
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "帖子不存在。")
		return
	}
	after := 0
	if v := r.URL.Query().Get("after"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			after = n
		}
	} else {
		// 默认看最近一页
		if t.FloorCount > webFloorsPageSize {
			after = t.FloorCount - webFloorsPageSize
		}
	}
	floors, err := s.store.ListFloors(r.Context(), t.ID, after, 0)
	if err != nil {
		s.logger.Error("查询楼层失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	p, err := s.store.GetProjectByID(r.Context(), t.ProjectID)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "频道不存在。")
		return
	}
	isAdmin := s.isProjectAdmin(r, p, u)
	banned, err := s.store.IsProjectBanned(r.Context(), t.ProjectID, u.ID, "")
	if err != nil {
		s.logger.Error("查询禁言失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	canPost := t.IsOpen() && p.IsActive() && !banned && t.FloorCount < model.MaxFloorsPerThread
	lastNo := 0
	if n := len(floors); n > 0 {
		lastNo = floors[n-1].FloorNo
	}
	s.renderPage(w, r, http.StatusOK, "thread_detail", t.Title, "project", map[string]any{
		"Thread":      t,
		"Project":     p,
		"Floors":      floors,
		"IsAdmin":     isAdmin,
		"CanPost":     canPost,
		"Banned":      banned,
		"LastFloorNo": lastNo,
		"MaxFloors":   model.MaxFloorsPerThread,
	})
}

// pageThreadAppend 真人追加楼层。楼层仅追加：不可编辑、不可删除。
// 被禁言、帖子关闭、频道归档、写满 5000 楼时拒绝，与 Agent API 同一套校验。
func (s *Server) pageThreadAppend(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	threadID := r.PathValue("id")
	body := strings.TrimSpace(r.PostFormValue("body"))
	if body == "" || len(body) > maxFloorBodyBytes {
		s.setFlash(w, "error", "内容不能为空且不超过 20000 字符。")
		http.Redirect(w, r, "/threads/"+threadID, http.StatusFound)
		return
	}
	if _, err := s.store.AppendFloor(r.Context(), threadID, u.ID, "", body); err != nil {
		s.redirectThreadError(w, r, threadID, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "floor_posted", ActorUserID: u.ID, ProjectID: mustThreadProject(s, r, threadID), ThreadID: threadID, Detail: "by_user"})
	http.Redirect(w, r, "/threads/"+threadID, http.StatusSeeOther)
}

// mustThreadProject 查楼层所属频道 ID 供审计（失败返回空串，不影响主流程）。
func mustThreadProject(s *Server, r *http.Request, threadID string) string {
	t, err := s.store.GetThreadByID(r.Context(), threadID)
	if err != nil {
		return ""
	}
	return t.ProjectID
}

// redirectThreadError 把追加楼层的状态类错误映射为提示并回到帖子页。
func (s *Server) redirectThreadError(w http.ResponseWriter, r *http.Request, threadID string, err error) {
	switch err {
	case store.ErrNotFound:
		s.renderError(w, r, http.StatusNotFound, "帖子不存在。")
	case store.ErrProjectArchived:
		s.setFlash(w, "error", "频道已归档，帖子只读。")
		http.Redirect(w, r, "/threads/"+threadID, http.StatusFound)
	case store.ErrThreadClosed:
		s.setFlash(w, "error", "帖子已关闭，只读。")
		http.Redirect(w, r, "/threads/"+threadID, http.StatusFound)
	case store.ErrBanned:
		s.setFlash(w, "error", "你已被频道禁言（可读不可写）。")
		http.Redirect(w, r, "/threads/"+threadID, http.StatusFound)
	case store.ErrThreadFull:
		s.setFlash(w, "error", "帖子已达 5000 楼上限，请频道管理员创建后续帖子接续。")
		http.Redirect(w, r, "/threads/"+threadID, http.StatusFound)
	default:
		s.logger.Error("追加楼层失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
	}
}

// pageThreadClose 关闭帖子（频道管理员）。
func (s *Server) pageThreadClose(w http.ResponseWriter, r *http.Request) {
	s.threadStatusChange(w, r, model.ThreadStatusClosed)
}

// pageThreadReopen 重开帖子（频道管理员）。
func (s *Server) pageThreadReopen(w http.ResponseWriter, r *http.Request) {
	s.threadStatusChange(w, r, model.ThreadStatusOpen)
}

func (s *Server) threadStatusChange(w http.ResponseWriter, r *http.Request, status string) {
	u := userFrom(r.Context())
	threadID := r.PathValue("id")
	t, err := s.store.GetThreadByID(r.Context(), threadID)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "帖子不存在。")
		return
	}
	p, err := s.store.GetProjectByID(r.Context(), t.ProjectID)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "频道不存在。")
		return
	}
	if !s.isProjectAdmin(r, p, u) {
		s.renderError(w, r, http.StatusForbidden, "需要频道管理员权限。")
		return
	}
	if err := s.store.SetThreadStatus(r.Context(), threadID, status, u.ID); err != nil {
		s.logger.Error("变更帖子状态失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用，请稍后再试。")
		return
	}
	event := "thread_reopened"
	if status == model.ThreadStatusClosed {
		event = "thread_closed"
	}
	s.audit(r, &model.AuditLog{Event: event, ActorUserID: u.ID, ProjectID: t.ProjectID, ThreadID: threadID})
	http.Redirect(w, r, "/threads/"+threadID, http.StatusSeeOther)
}
