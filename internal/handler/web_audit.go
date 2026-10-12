package handler

import (
	"net/http"

	"agentpermit/internal/model"
)

const auditPageSize = 200

type auditRow struct {
	*model.AuditLog
	Source string
	Scope  string
}

// auditPresentation 解释已知机器事件；未知历史事件不推测请求来源。
func auditPresentation(log *model.AuditLog) auditRow {
	row := auditRow{AuditLog: log, Source: "未标明", Scope: "-"}
	switch log.Event {
	case "authorize_allowed", "authorize_denied":
		row.Source, row.Scope = "服务授权校验", "能力访问"
	case "floor_posted", "floor_denied":
		row.Scope = "留言板发言"
		if log.CredentialID != "" {
			row.Source = "调用凭证请求"
		} else if log.Detail == "by_user" {
			row.Source = "网页会话"
		}
	case "project_user_banned", "project_user_unbanned":
		row.Source, row.Scope = "网页会话", "整个账号的发言"
	case "project_agent_banned", "project_agent_unbanned":
		row.Source, row.Scope = "网页会话", "指定凭证的发言"
	case "agent_created", "agent_revoked", "agent_token_rotated":
		row.Source, row.Scope = "网页会话", "单条调用凭证"
	case "user_disabled", "user_enabled":
		row.Source, row.Scope = "网页会话", "账号状态"
	case "capability_denylist_added", "capability_denylist_removed", "capability_allowlist_added", "capability_allowlist_removed":
		row.Source, row.Scope = "网页会话", "账号能力权限"
	case "login_success", "login_failed", "logout", "user_registered":
		row.Source, row.Scope = "网页登录", "账号会话"
	case "capability_created", "capability_updated", "capability_enabled", "capability_disabled", "capability_access_mode_changed", "capability_service_token_created", "capability_service_token_rotated", "capability_version_published", "capability_latest_moved":
		row.Source, row.Scope = "网页会话", "能力管理"
	case "project_created", "project_admin_added", "project_admin_removed", "project_archived", "project_unarchived", "agentsmd_published", "agentsmd_latest_moved":
		row.Source, row.Scope = "网页会话", "项目管理"
	case "thread_created", "thread_closed", "thread_reopened":
		row.Source, row.Scope = "网页会话", "留言板管理"
	}
	return row
}

func (s *Server) pageAudit(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	// 普通用户只能看与自己账号相关的事件和自己拥有能力上的授权事件。
	var logs []*model.AuditLog
	var err error
	if u.IsAdmin() {
		logs, err = s.store.ListAuditAdmin(r.Context(), auditPageSize)
	} else {
		logs, err = s.store.ListAuditForUser(r.Context(), u.ID, auditPageSize)
	}
	if err != nil {
		s.logger.Error("查询审计失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	rows := make([]auditRow, 0, len(logs))
	for _, log := range logs {
		rows = append(rows, auditPresentation(log))
	}
	s.renderPage(w, r, http.StatusOK, "audit", "审计记录", "audit", map[string]any{
		"Logs":    rows,
		"Count":   len(logs),
		"IsAdmin": u.IsAdmin(),
	})
}
