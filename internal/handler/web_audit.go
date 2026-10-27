package handler

import (
	"net/http"
	"strings"

	"agentpermit/internal/model"
)

const auditPageSize = 200

type auditRow struct {
	*model.AuditLog
	Source string
	Scope  string
}

// auditPresentation 解释已知机器事件；未知历史事件不推测请求来源。
// 临时授信签发按写入时的 via= 标注区分来源，历史无标注记录保持“未标明”。
func auditPresentation(log *model.AuditLog) auditRow {
	row := auditRow{AuditLog: log, Source: "未标明", Scope: "-"}
	switch log.Event {
	case "authorize_allowed", "authorize_denied":
		row.Source, row.Scope = "服务授权校验", "能力访问"
	case "capability_denylist_added", "capability_denylist_removed", "capability_allowlist_added", "capability_allowlist_removed":
		row.Source, row.Scope = "网页会话", "账号能力权限"
	case "capability_created", "capability_updated", "capability_enabled", "capability_disabled", "capability_access_mode_changed", "capability_service_token_created", "capability_service_token_rotated", "capability_version_published", "capability_latest_moved":
		row.Source, row.Scope = "网页会话", "能力管理"
	case "user_password_changed", "user_password_change_failed":
		row.Source, row.Scope = "网页会话", "个人密码管理"
	case "agent_work_denied":
		row.Source, row.Scope = "调用凭证请求", "作业管控"
	case "floor_posted", "floor_denied":
		row.Scope = "帖子发言"
		if log.CredentialID != "" {
			row.Source = "调用凭证请求"
		} else if log.Detail == "by_user" {
			row.Source = "网页会话"
		}
	case "temporary_grant_issued":
		row.Scope = "临时授信签发"
		switch {
		case strings.Contains(log.Detail, "via=agent_api"):
			row.Source = "调用凭证请求"
		case strings.Contains(log.Detail, "via=web"):
			row.Source = "网页会话"
		}
	case "temporary_grant_revoked":
		row.Source, row.Scope = "网页会话", "临时授信撤销"
	case "trust_verified", "trust_verification_denied":
		row.Source, row.Scope = "Server回调核验", "临时授信核验"
	case "server_saved":
		row.Source, row.Scope = "网页会话", "Server登记"
	case "server_key_rotated":
		row.Source, row.Scope = "网页会话", "Server接入凭证轮换"
	case "field_group_created":
		row.Source, row.Scope = "网页会话", "变量编组登记"
	case "work_ban_saved", "work_ban_released":
		row.Source, row.Scope = "网页会话", "工作封禁"
	case "holiday_scheduled", "holiday_unlocked", "holiday_unlock_failed":
		row.Source, row.Scope = "网页会话", "节假日封网"
	case "holiday_countdown", "holiday_active", "holiday_ended":
		row.Source, row.Scope = "系统状态迁移", "节假日封网"
	case "project_user_banned", "project_user_unbanned":
		row.Source, row.Scope = "网页会话", "整个账号的发言"
	case "project_agent_banned", "project_agent_unbanned":
		row.Source, row.Scope = "网页会话", "指定凭证的发言"
	case "agent_created", "agent_revoked", "agent_token_rotated":
		row.Source, row.Scope = "网页会话", "单条调用凭证"
	case "user_disabled", "user_enabled":
		row.Source, row.Scope = "网页会话", "账号状态"
	case "user_created":
		row.Source, row.Scope = "网页会话", "账号开通"
	case "login_success", "login_failed", "logout", "user_registered":
		row.Source, row.Scope = "网页登录", "账号会话"
	case "project_created", "project_admin_added", "project_admin_removed", "project_archived", "project_unarchived", "agentsmd_published", "agentsmd_latest_moved":
		row.Source, row.Scope = "网页会话", "频道管理"
	case "thread_created", "thread_closed", "thread_reopened":
		row.Source, row.Scope = "网页会话", "帖子管理"
	}
	return row
}

func (s *Server) pageAudit(w http.ResponseWriter, r *http.Request) {
	s.renderAuditPage(w, r, false)
}

func (s *Server) pageAdminAudit(w http.ResponseWriter, r *http.Request) {
	s.renderAuditPage(w, r, true)
}

func (s *Server) renderAuditPage(w http.ResponseWriter, r *http.Request, global bool) {
	u := userFrom(r.Context())
	// 个人入口始终按当前账号筛选，全局入口由路由要求管理员权限。
	var logs []*model.AuditLog
	var err error
	title, pageKey := "审计我的Agent", "audit"
	if global {
		title, pageKey = "全局审计", "admin-audit"
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
	s.renderPage(w, r, http.StatusOK, "audit", title, pageKey, map[string]any{
		"Logs":   rows,
		"Count":  len(logs),
		"Global": global,
	})
}
