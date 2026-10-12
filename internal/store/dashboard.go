package store

import (
	"context"
	"database/sql"
	"time"

	"agentpermit/internal/model"
)

// Dashboard 聚合完整时间窗口；不截断为审计页面的最近 200 条。
func (s *Store) Dashboard(ctx context.Context, userID string, all bool, start, end time.Time, buckets int) (*model.DashboardSnapshot, error) {
	// 一个只读快照避免刷新期间新增审计导致总数、趋势与榜单彼此不一致。
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	scope, scopeArgs := auditScope(userID, all)
	where := `a.created_at >= ? AND a.created_at < ? AND ` + scope
	args := append([]any{fmtTime(start), fmtTime(end)}, scopeArgs...)
	out := &model.DashboardSnapshot{
		Trend:             make([]model.DashboardPoint, buckets),
		CapabilityRanking: []model.DashboardRank{}, CredentialRanking: []model.DashboardRank{},
		Activity: []model.DashboardActivity{},
	}
	err = tx.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(a.event='authorize_allowed'),0), COALESCE(SUM(a.event='authorize_denied'),0),
		COALESCE(SUM(a.event='floor_posted'),0),
		COUNT(DISTINCT CASE WHEN a.event IN ('authorize_allowed','authorize_denied','floor_posted','floor_denied') THEN a.agent_id END)
		FROM audit_logs a WHERE `+where, args...).Scan(&out.Allowed, &out.Denied, &out.Posts, &out.ActiveCredentials)
	if err != nil {
		return nil, err
	}
	out.Authorizations = out.Allowed + out.Denied
	if out.Authorizations > 0 {
		rate := float64(out.Allowed) * 100 / float64(out.Authorizations)
		out.ApprovalRate = &rate
	}
	interval := int64(end.Sub(start).Seconds()) / int64(buckets)
	zone := time.FixedZone("Asia/Shanghai", 8*60*60)
	for i := range out.Trend {
		t := start.Add(time.Duration(int64(i)*interval) * time.Second).In(zone)
		label := t.Format("15:04")
		if end.Sub(start) > 24*time.Hour {
			label = t.Format("01-02")
		}
		out.Trend[i].Label = label
	}
	trendArgs := append([]any{start.Unix(), interval}, args...)
	rows, err := tx.QueryContext(ctx, `SELECT
		CAST((CAST(strftime('%s',a.created_at) AS INTEGER)-?)/? AS INTEGER) AS bucket,
		SUM(a.event='authorize_allowed'), SUM(a.event='authorize_denied')
		FROM audit_logs a WHERE `+where+` AND a.event IN ('authorize_allowed','authorize_denied') GROUP BY bucket`, trendArgs...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var index int
		var allowed, denied int64
		if err := rows.Scan(&index, &allowed, &denied); err != nil {
			rows.Close()
			return nil, err
		}
		if index >= 0 && index < buckets {
			out.Trend[index].Allowed, out.Trend[index].Denied = allowed, denied
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out.CapabilityRanking, err = s.dashboardRanks(ctx, tx, `SELECT c.id, COALESCE(v.name,'未发布能力'), u.display_name, COUNT(*)
		FROM audit_logs a JOIN capabilities c ON c.id=a.capability_id
		JOIN users u ON u.id=c.owner_user_id
		LEFT JOIN capability_versions v ON v.capability_id=c.id AND v.version=c.latest_version
		WHERE `+where+` AND a.event IN ('authorize_allowed','authorize_denied')
		GROUP BY c.id ORDER BY COUNT(*) DESC, c.id LIMIT 5`, args)
	if err != nil {
		return nil, err
	}
	out.CredentialRanking, err = s.dashboardRanks(ctx, tx, `SELECT c.id, c.name, u.display_name, COUNT(*)
		FROM audit_logs a JOIN agents c ON c.id=a.agent_id JOIN users u ON u.id=c.owner_user_id
		WHERE `+where+` AND a.event IN ('authorize_allowed','authorize_denied','floor_posted','floor_denied')
		GROUP BY c.id ORDER BY COUNT(*) DESC, c.id LIMIT 5`, args)
	if err != nil {
		return nil, err
	}
	err = tx.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM capabilities WHERE owner_user_id=?),
		(SELECT COUNT(*) FROM agents WHERE owner_user_id=? AND status='active'),
		(SELECT COUNT(*) FROM projects), (SELECT COUNT(*) FROM threads)`, userID, userID).
		Scan(&out.Resources.Capabilities, &out.Resources.Credentials, &out.Resources.Channels, &out.Resources.Threads)
	if err != nil {
		return nil, err
	}
	// 动态只取有限展示字段，避免把审计 detail、请求地址或凭证提示交给浏览器。
	rows, err = tx.QueryContext(ctx, `SELECT a.created_at,a.event,a.outcome,
		COALESCE(v.name,pr.name,credential.name,u.display_name,'账号事件')
		FROM audit_logs a LEFT JOIN capabilities c ON c.id=a.capability_id
		LEFT JOIN capability_versions v ON v.capability_id=c.id AND v.version=c.latest_version
		LEFT JOIN projects pr ON pr.id=a.project_id LEFT JOIN agents credential ON credential.id=a.agent_id
		LEFT JOIN users u ON u.id=a.actor_user_id
		WHERE `+where+` ORDER BY a.created_at DESC,a.id DESC LIMIT 4`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item model.DashboardActivity
		var timestamp, event string
		if err := rows.Scan(&timestamp, &event, &item.Outcome, &item.Resource); err != nil {
			return nil, err
		}
		item.Time, err = parseTime(timestamp)
		if err != nil {
			return nil, err
		}
		item.Title = dashboardEventTitle(event)
		out.Activity = append(out.Activity, item)
	}
	return out, rows.Err()
}

func (s *Store) dashboardRanks(ctx context.Context, tx *sql.Tx, query string, args []any) ([]model.DashboardRank, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.DashboardRank{}
	for rows.Next() {
		var rank model.DashboardRank
		if err := rows.Scan(&rank.ID, &rank.Name, &rank.Owner, &rank.Count); err != nil {
			return nil, err
		}
		out = append(out, rank)
	}
	return out, rows.Err()
}

func dashboardEventTitle(event string) string {
	switch event {
	case "authorize_allowed":
		return "授权允许"
	case "authorize_denied":
		return "授权拒绝"
	case "floor_posted":
		return "协作发言"
	case "floor_denied":
		return "发言受限"
	case "agent_created":
		return "创建凭证"
	case "agent_revoked":
		return "撤销凭证"
	case "agent_token_rotated":
		return "轮换凭证"
	case "login_success":
		return "账号登录"
	case "capability_created", "capability_version_published":
		return "能力发布"
	case "project_created":
		return "创建频道"
	case "thread_created":
		return "创建留言板"
	default:
		return "管理操作"
	}
}
