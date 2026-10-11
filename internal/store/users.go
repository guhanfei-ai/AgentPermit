package store

import (
	"context"
	"database/sql"

	"agentpermit/internal/model"
)

const userColumns = `id, username, display_name, password_hash, role, status, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	var u model.User
	var createdAt, updatedAt string
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.Status, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if u.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if u.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateUser 插入新用户。
func (s *Store) CreateUser(ctx context.Context, u *model.User) error {
	u.CreatedAt = now()
	u.UpdatedAt = u.CreatedAt
	_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, username, display_name, password_hash, role, status, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		u.ID, u.Username, u.DisplayName, u.PasswordHash, u.Role, u.Status, fmtTime(u.CreatedAt), fmtTime(u.UpdatedAt))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// UpdateUserPassword 更新密码哈希（目前仅初始化管理员流程使用）。
func (s *Store) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=?, updated_at=? WHERE id=?`, passwordHash, fmtTime(now()), userID)
	return err
}

// GetUserByUsername 按用户名查询。
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username=?`, username))
}

// GetUserByID 按 ID 查询。
func (s *Store) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id=?`, id))
}

// ListUsers 返回全部用户（管理员页面用，第一版规模小不分页）。
func (s *Store) ListUsers(ctx context.Context) ([]*model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SearchUsers 按用户名或显示名前缀搜索（黑名单/白名单添加用），排除指定用户。
func (s *Store) SearchUsers(ctx context.Context, q string, excludeUserID string, limit int) ([]*model.User, error) {
	if limit <= 0 || limit > 20 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users
		WHERE (username LIKE ? OR display_name LIKE ?) AND id != ?
		ORDER BY username LIMIT ?`,
		q+"%", q+"%", excludeUserID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserStatus 启用/禁用用户。
func (s *Store) SetUserStatus(ctx context.Context, userID, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET status=?, updated_at=? WHERE id=?`, status, fmtTime(now()), userID)
	return err
}
