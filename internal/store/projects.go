package store

import (
	"context"
	"database/sql"
	"errors"

	"agentpermit/internal/model"
)

const projectColumns = `p.id, p.slug, p.name, p.description, p.status, p.created_by, p.created_at, p.updated_at,
	COALESCE(u.username,''), COALESCE(u.display_name,''),
	(SELECT COUNT(*) FROM threads t WHERE t.project_id = p.id)`

const projectFrom = ` FROM projects p
	LEFT JOIN users u ON u.id = p.created_by `

func scanProject(row interface{ Scan(...any) error }) (*model.Project, error) {
	var p model.Project
	var createdAt, updatedAt string
	if err := row.Scan(&p.ID, &p.Slug, &p.Name, &p.Description, &p.Status, &p.CreatedBy, &createdAt, &updatedAt,
		&p.CreatedByUsername, &p.CreatedByDisplay, &p.ThreadCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if p.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if p.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

// CreateProject 创建频道：创建者自动写入 project_admins，并初始化 AGENTS.md 文档行。
func (s *Store) CreateProject(ctx context.Context, p *model.Project) error {
	p.CreatedAt = now()
	p.UpdatedAt = p.CreatedAt
	return s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO projects (id, slug, name, description, status, created_by, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?)`,
			p.ID, p.Slug, p.Name, p.Description, p.Status, p.CreatedBy, fmtTime(p.CreatedAt), fmtTime(p.UpdatedAt))
		if isUniqueViolation(err) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_admins (project_id, user_id, created_at) VALUES (?,?,?)`,
			p.ID, p.CreatedBy, fmtTime(p.CreatedAt)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO project_docs (project_id) VALUES (?)`, p.ID)
		return err
	})
}

// GetProjectByID 按 ID 查询频道。
func (s *Store) GetProjectByID(ctx context.Context, id string) (*model.Project, error) {
	return scanProject(s.db.QueryRowContext(ctx, `SELECT `+projectColumns+projectFrom+` WHERE p.id=?`, id))
}

// GetProjectBySlug 按 slug 查询频道。
func (s *Store) GetProjectBySlug(ctx context.Context, slug string) (*model.Project, error) {
	return scanProject(s.db.QueryRowContext(ctx, `SELECT `+projectColumns+projectFrom+` WHERE p.slug=?`, slug))
}

// ListProjects 列出全部频道（AI聊天广场页），活跃在前、更新时间倒序。
func (s *Store) ListProjects(ctx context.Context) ([]*model.Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+projectColumns+projectFrom+` ORDER BY p.status='archived', p.updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListProjectsPage 分页列出频道，排序与 ListProjects 一致（活跃在前、更新时间倒序）。
// limit<=0 表示不限量（仅跳过 offset），offset<0 视为 0；total 始终为频道总数，
// 不受 limit/offset 影响。参数合法性由调用方（API 层）负责校验。
func (s *Store) ListProjectsPage(ctx context.Context, limit, offset int) ([]*model.Project, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects`).Scan(&total); err != nil {
		return nil, 0, err
	}
	if offset < 0 {
		offset = 0
	}
	q := `SELECT ` + projectColumns + projectFrom + ` ORDER BY p.status='archived', p.updated_at DESC`
	args := []any{}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	if offset > 0 {
		// SQLite 要求 OFFSET 必须与 LIMIT 同现；-1 表示不限量。
		if limit <= 0 {
			q += ` LIMIT -1`
		}
		q += ` OFFSET ?`
		args = append(args, offset)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*model.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// SetProjectStatus 归档/恢复频道。
func (s *Store) SetProjectStatus(ctx context.Context, id, status string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE projects SET status=?, updated_at=? WHERE id=?`,
		status, fmtTime(now()), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// IsProjectAdmin 报告用户是否频道管理员（创建时已把创建者写入 admins 表）。
func (s *Store) IsProjectAdmin(ctx context.Context, projectID, userID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM project_admins WHERE project_id=? AND user_id=?`, projectID, userID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListProjectAdmins 列出频道管理员（联查展示名）。
func (s *Store) ListProjectAdmins(ctx context.Context, projectID string) ([]*model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id, u.username, u.display_name, u.role, u.status, u.created_at, u.updated_at
		FROM project_admins pa JOIN users u ON u.id = pa.user_id
		WHERE pa.project_id=? ORDER BY pa.created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.User
	for rows.Next() {
		var u model.User
		var createdAt, updatedAt string
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.Status, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		if u.CreatedAt, err = parseTime(createdAt); err != nil {
			return nil, err
		}
		if u.UpdatedAt, err = parseTime(updatedAt); err != nil {
			return nil, err
		}
		out = append(out, &u)
	}
	return out, rows.Err()
}

// AddProjectAdmin 新增频道管理员（按用户 ID）。
func (s *Store) AddProjectAdmin(ctx context.Context, projectID, userID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO project_admins (project_id, user_id, created_at) VALUES (?,?,?)`,
		projectID, userID, fmtTime(now()))
	if isUniqueViolation(err) {
		return nil // 已是管理员，幂等
	}
	return err
}

// RemoveProjectAdmin 移除频道管理员。
func (s *Store) RemoveProjectAdmin(ctx context.Context, projectID, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM project_admins WHERE project_id=? AND user_id=?`, projectID, userID)
	return err
}

// AddProjectBan 添加禁言。credentialID 为空为账号级（覆盖其所有调用凭证与本人网页发言）。
func (s *Store) AddProjectBan(ctx context.Context, b *model.ProjectBan) error {
	b.CreatedAt = now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO project_bans (project_id, user_id, agent_id, reason, banned_by, created_at)
		VALUES (?,?,?,?,?,?)`,
		b.ProjectID, b.UserID, b.CredentialID, b.Reason, b.BannedBy, fmtTime(b.CreatedAt))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// RemoveProjectBan 解除禁言（账号级传 credentialID 空串）。
func (s *Store) RemoveProjectBan(ctx context.Context, projectID, userID, credentialID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM project_bans WHERE project_id=? AND user_id=? AND agent_id=?`,
		projectID, userID, credentialID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const banColumns = `b.project_id, b.user_id, b.agent_id, b.reason, b.banned_by, b.created_at,
	COALESCE(u.username,''), COALESCE(u.display_name,''), COALESCE(a.name,''), COALESCE(bu.username,'')`

func scanBan(row interface{ Scan(...any) error }) (*model.ProjectBan, error) {
	var b model.ProjectBan
	var createdAt string
	var bannedBy sql.NullString
	if err := row.Scan(&b.ProjectID, &b.UserID, &b.CredentialID, &b.Reason, &bannedBy, &createdAt,
		&b.Username, &b.DisplayName, &b.CredentialName, &b.BannedByUsername); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if b.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	b.BannedBy = bannedBy.String
	return &b, nil
}

// ListProjectBans 列出频道禁言条目（联查账号与凭证名称）。
func (s *Store) ListProjectBans(ctx context.Context, projectID string) ([]*model.ProjectBan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+banColumns+` FROM project_bans b
		LEFT JOIN users u ON u.id = b.user_id
		LEFT JOIN agents a ON a.id = b.agent_id
		LEFT JOIN users bu ON bu.id = b.banned_by
		WHERE b.project_id=? ORDER BY b.created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.ProjectBan
	for rows.Next() {
		b, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// IsProjectBanned 判断发言资格：credentialID 为空（网页会话发言）只查账号级禁言；
// credentialID 非空时账号级或单凭证限制任一命中即禁言。
func (s *Store) IsProjectBanned(ctx context.Context, projectID, userID, credentialID string) (bool, error) {
	q := `SELECT 1 FROM project_bans WHERE project_id=? AND user_id=? AND agent_id=''`
	args := []any{projectID, userID}
	if credentialID != "" {
		q += ` OR (project_id=? AND user_id=? AND agent_id=?)`
		args = append(args, projectID, userID, credentialID)
	}
	var one int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
