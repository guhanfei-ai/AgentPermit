package store

import (
	"context"
	"database/sql"

	"agentpermit/internal/model"
)

// InsertAudit 写入审计记录。detail 只允许脱敏后的有限字段。
func (s *Store) InsertAudit(ctx context.Context, e *model.AuditLog) error {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO audit_logs (created_at, event, actor_user_id, agent_id, capability_id, project_id, thread_id, subject_user_id, outcome, reason, request_id, detail)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		fmtTime(e.CreatedAt), e.Event, nullStr(e.ActorUserID), nullStr(e.CredentialID), nullStr(e.CapabilityID), nullStr(e.ProjectID), nullStr(e.ThreadID), nullStr(e.SubjectUserID),
		e.Outcome, e.Reason, e.RequestID, e.Detail)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

const auditColumns = `a.id, a.created_at, a.event, a.actor_user_id, a.agent_id, a.capability_id, a.project_id, a.thread_id, a.subject_user_id, a.outcome, a.reason, a.request_id, a.detail,
	COALESCE(u.username,''), COALESCE(c.name,''), COALESCE(pr.name,''),
	COALESCE(subject.username,''), COALESCE(credential.name,''), COALESCE(credential_owner.username,'')`

func scanAudit(row interface{ Scan(...any) error }) (*model.AuditLog, error) {
	var e model.AuditLog
	var createdAt string
	var actorID, credentialID, capID, projectID, threadID, subjectID sql.NullString
	if err := row.Scan(&e.ID, &createdAt, &e.Event, &actorID, &credentialID, &capID, &projectID, &threadID, &subjectID, &e.Outcome, &e.Reason, &e.RequestID, &e.Detail, &e.ActorUsername, &e.CapabilityName, &e.ProjectName,
		&e.SubjectUsername, &e.CredentialName, &e.CredentialOwnerUsername); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if e.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	e.ActorUserID, e.CredentialID, e.CapabilityID, e.ProjectID, e.ThreadID, e.SubjectUserID = actorID.String, credentialID.String, capID.String, projectID.String, threadID.String, subjectID.String
	return &e, nil
}

const auditFrom = ` FROM audit_logs a
	LEFT JOIN users u ON u.id = a.actor_user_id
	LEFT JOIN capabilities c ON c.id = a.capability_id
	LEFT JOIN projects pr ON pr.id = a.project_id
	LEFT JOIN users subject ON subject.id = a.subject_user_id
	LEFT JOIN agents credential ON credential.id = a.agent_id
	LEFT JOIN users credential_owner ON credential_owner.id = credential.owner_user_id `

// auditScope 与审计页和统计面板共用，账号范围只由可信的登录身份决定。
func auditScope(userID string, all bool) (string, []any) {
	if all {
		return "1=1", nil
	}
	return `(a.actor_user_id = ? OR a.subject_user_id = ?
		OR (a.event IN ('authorize_allowed','authorize_denied') AND a.capability_id IN
		(SELECT id FROM capabilities WHERE owner_user_id = ?)))`, []any{userID, userID, userID}
}

// ListAuditAdmin 返回全局审计（管理员）。
func (s *Store) ListAuditAdmin(ctx context.Context, limit int) ([]*model.AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditColumns+auditFrom+` ORDER BY a.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AuditLog
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAuditForUser 返回与用户相关的审计：
// 1) 该账号发起的事件；2) 针对该账号的授权或管理事件；3) 该账号拥有能力上的授权事件。
// 普通用户不能浏览其他用户操作记录。
func (s *Store) ListAuditForUser(ctx context.Context, userID string, limit int) ([]*model.AuditLog, error) {
	scope, args := auditScope(userID, false)
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditColumns+auditFrom+` WHERE `+scope+`
		ORDER BY a.id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AuditLog
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
