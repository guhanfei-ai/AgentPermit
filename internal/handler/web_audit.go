package handler

import (
	"net/http"

	"agentpermit/internal/model"
)

const auditPageSize = 200

func (s *Server) pageAudit(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	// 普通用户只能看与自己相关的身份事件和自己拥有能力的访问事件
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
	s.renderPage(w, r, http.StatusOK, "audit", "审计记录", "audit", map[string]any{
		"Logs":    logs,
		"Count":   len(logs),
		"IsAdmin": u.IsAdmin(),
	})
}
