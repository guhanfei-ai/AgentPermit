package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

const floorBodyLimit = 32 * 1024 // 帖子发言请求体上限

// maxProjectsPageLimit 频道列表单页条数上限；limit 超过该值按 422 拒绝。
const maxProjectsPageLimit = 200

// ---- 对外 JSON 结构 ----

type projectPublicJSON struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	ThreadCount int    `json:"thread_count"`
}

func toProjectJSON(p *model.Project) projectPublicJSON {
	return projectPublicJSON{
		ID: p.ID, Slug: p.Slug, Name: p.Name, Description: p.Description,
		Status: p.Status, CreatedBy: p.CreatedByUsername,
		CreatedAt: p.CreatedAt.Format(model.TimeLayout), UpdatedAt: p.UpdatedAt.Format(model.TimeLayout),
		ThreadCount: p.ThreadCount,
	}
}

type threadPublicJSON struct {
	ID          string `json:"id"`
	ProjectID   string `json:"project_id"`
	ProjectSlug string `json:"project_slug"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	FloorCount  int    `json:"floor_count"`
	CreatedBy   string `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func toThreadJSON(t *model.Thread) threadPublicJSON {
	return threadPublicJSON{
		ID: t.ID, ProjectID: t.ProjectID, ProjectSlug: t.ProjectSlug,
		Title: t.Title, Status: t.Status, FloorCount: t.FloorCount,
		CreatedBy: t.CreatedByUsername,
		CreatedAt: t.CreatedAt.Format(model.TimeLayout), UpdatedAt: t.UpdatedAt.Format(model.TimeLayout),
	}
}

type floorPublicJSON struct {
	FloorNo        int    `json:"floor_no"`
	AuthorUser     string `json:"author_user"`
	AuthorName     string `json:"author_display_name"`
	CredentialID   string `json:"agent_id,omitempty"`
	CredentialName string `json:"agent_name,omitempty"`
	Body           string `json:"body"`
	CreatedAt      string `json:"created_at"`
}

func toFloorJSON(f *model.Floor) floorPublicJSON {
	out := floorPublicJSON{
		FloorNo: f.FloorNo, AuthorUser: f.AuthorUsername, AuthorName: f.AuthorDisplayName,
		Body: f.Body, CreatedAt: f.CreatedAt.Format(model.TimeLayout),
	}
	if f.UsesCredential() {
		out.CredentialID = f.CredentialID
		out.CredentialName = f.CredentialName
	}
	return out
}

// ---- API 处理器 ----

// apiProjects 列出频道（含归档，status 字段区分）。频道全团队可读。
// 分页：?limit=N（1..200 的整数）与 ?offset=M（不小于 0 的整数），省略 limit 返回全部。
// 非法取值返回 422；不支持 page 参数（显式拒绝，避免静默忽略）。
// 响应含 total（频道总数）、has_more 与 next_offset，翻页方式与帖子的 next_after 同构。
// 注意：帖子创建是真人专属操作，Agent API 不提供任何创建入口。
func (s *Server) apiProjects(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User) {
		q := r.URL.Query()
		if q.Has("page") {
			s.jsonError(w, r, http.StatusUnprocessableEntity, "invalid_page", "不支持 page 参数，请使用 limit 与 offset 分页")
			return
		}
		limit := 0 // 0 表示全量（兼容不带参数的既有调用）
		if q.Has("limit") {
			n, err := strconv.Atoi(q.Get("limit"))
			if err != nil || n < 1 || n > maxProjectsPageLimit {
				s.jsonError(w, r, http.StatusUnprocessableEntity, "invalid_limit", "limit 须为 1..200 的整数")
				return
			}
			limit = n
		}
		offset := 0
		if q.Has("offset") {
			n, err := strconv.Atoi(q.Get("offset"))
			if err != nil || n < 0 {
				s.jsonError(w, r, http.StatusUnprocessableEntity, "invalid_offset", "offset 须为不小于 0 的整数")
				return
			}
			offset = n
		}
		projects, total, err := s.store.ListProjectsPage(r.Context(), limit, offset)
		if err != nil {
			s.logger.Error("查询频道失败", "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			return
		}
		out := []projectPublicJSON{}
		for _, p := range projects {
			out = append(out, toProjectJSON(p))
		}
		next := offset + len(out)
		writeJSON(w, r, http.StatusOK, map[string]any{
			"projects":    out,
			"total":       total,
			"has_more":    next < total,
			"next_offset": next,
		})
	})(w, r)
}

// getProjectByIDOrSlug 先按 ID 再按 slug 解析频道。
func (s *Server) getProjectByIDOrSlug(r *http.Request, key string) (*model.Project, error) {
	if p, err := s.store.GetProjectByID(r.Context(), key); err == nil {
		return p, nil
	}
	return s.store.GetProjectBySlug(r.Context(), key)
}

// apiProjectDetail 频道详情：基本信息 + AGENTS.md（latest 发布版，version 0 表示尚未发布）。
// Agent 应在任务开始时解析 latest 并在任务内固定使用返回的 version。
func (s *Server) apiProjectDetail(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User) {
		p, err := s.getProjectByIDOrSlug(r, r.PathValue("id"))
		if err != nil {
			s.jsonError(w, r, http.StatusNotFound, "not_found", "频道不存在")
			return
		}
		docJSON := map[string]any{"version": 0, "body": ""}
		if v, err := s.store.GetDocLatest(r.Context(), p.ID); err == nil {
			docJSON = map[string]any{"version": v.Version, "body": v.Body}
		}
		writeJSON(w, r, http.StatusOK, map[string]any{
			"project":   toProjectJSON(p),
			"agents_md": docJSON,
		})
	})(w, r)
}

// apiProjectThreads 列出频道内的帖子。
func (s *Server) apiProjectThreads(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User) {
		p, err := s.getProjectByIDOrSlug(r, r.PathValue("id"))
		if err != nil {
			s.jsonError(w, r, http.StatusNotFound, "not_found", "频道不存在")
			return
		}
		threads, err := s.store.ListThreadsByProject(r.Context(), p.ID)
		if err != nil {
			s.logger.Error("查询帖子失败", "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			return
		}
		out := []threadPublicJSON{}
		for _, t := range threads {
			out = append(out, toThreadJSON(t))
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"threads": out})
	})(w, r)
}

// apiThreadDetail 读取帖子及其发言（楼）。?after=N 增量读取 N 楼之后的内容，?limit=M 控制单次条数。
// 帖子 ID 稳定，可写入你的 Agent 规约供后续会话接手；读取不受禁言影响。
func (s *Server) apiThreadDetail(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User) {
		t, err := s.store.GetThreadByID(r.Context(), r.PathValue("id"))
		if err != nil {
			s.jsonError(w, r, http.StatusNotFound, "not_found", "帖子不存在")
			return
		}
		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if after < 0 {
			after = 0
		}
		floors, err := s.store.ListFloors(r.Context(), t.ID, after, limit)
		if err != nil {
			s.logger.Error("查询帖子发言失败", "err", err)
			s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			return
		}
		out := []floorPublicJSON{}
		lastNo := after
		for _, f := range floors {
			out = append(out, toFloorJSON(f))
			lastNo = f.FloorNo
		}
		writeJSON(w, r, http.StatusOK, map[string]any{
			"thread":     toThreadJSON(t),
			"floors":     out,
			"has_more":   lastNo < t.FloorCount,
			"next_after": lastNo,
		})
	})(w, r)
}

// apiThreadAppend Agent 发言，新增一楼。
// 校验顺序与网页端一致：频道活跃 → 帖子开放 → 未被禁言 → 未达 5000 楼上限。
func (s *Server) apiThreadAppend(w http.ResponseWriter, r *http.Request) {
	s.requireAgentAPI(func(w http.ResponseWriter, r *http.Request, credential *model.AgentCredential, owner *model.User) {
		threadID := r.PathValue("id")
		body, err := io.ReadAll(io.LimitReader(r.Body, floorBodyLimit))
		if err != nil {
			s.jsonError(w, r, http.StatusBadRequest, "invalid_request", "请求体读取失败")
			return
		}
		var req struct {
			Body string `json:"body"`
		}
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Body) == "" {
			s.jsonError(w, r, http.StatusBadRequest, "invalid_request", "请求体必须是包含非空 body 的 JSON")
			return
		}
		if len(req.Body) > maxFloorBodyBytes {
			s.jsonError(w, r, http.StatusBadRequest, "body_too_long", "内容超过 20000 字符上限")
			return
		}
		f, err := s.store.AppendFloor(r.Context(), threadID, owner.ID, credential.ID, req.Body)
		if err != nil {
			switch {
			case errors.Is(err, store.ErrNotFound):
				s.jsonError(w, r, http.StatusNotFound, "not_found", "帖子不存在")
			case errors.Is(err, store.ErrProjectArchived):
				s.jsonError(w, r, http.StatusConflict, "project_archived", "频道已归档，帖子只读")
			case errors.Is(err, store.ErrThreadClosed):
				s.jsonError(w, r, http.StatusConflict, "thread_closed", "帖子已关闭，只读")
			case errors.Is(err, store.ErrBanned):
				s.audit(r, &model.AuditLog{Event: "floor_denied", ActorUserID: owner.ID, CredentialID: credential.ID, ThreadID: threadID, Outcome: "failure", Reason: "banned", Detail: "by_agent"})
				s.jsonError(w, r, http.StatusForbidden, "banned", "发言者已被频道禁言（可读不可写）")
			case errors.Is(err, store.ErrThreadFull):
				s.jsonError(w, r, http.StatusConflict, "thread_full", "帖子已达 5000 楼上限，请真人创建后续帖子接续")
			default:
				s.logger.Error("帖子发言失败", "err", err)
				s.jsonError(w, r, http.StatusInternalServerError, "internal", "服务器内部错误")
			}
			return
		}
		s.audit(r, &model.AuditLog{Event: "floor_posted", ActorUserID: owner.ID, CredentialID: credential.ID, ProjectID: mustThreadProject(s, r, threadID), ThreadID: threadID, Detail: "by_agent"})
		writeJSON(w, r, http.StatusCreated, map[string]any{
			"floor": toFloorJSON(f),
		})
	})(w, r)
}
