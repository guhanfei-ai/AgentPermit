package store

import (
	"context"
	"database/sql"

	"agentpermit/internal/model"
)

func scanListEntry(row interface{ Scan(...any) error }) (*model.ListEntry, error) {
	var e model.ListEntry
	var createdAt string
	if err := row.Scan(&e.CapabilityID, &e.UserID, &e.Username, &e.DisplayName, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if e.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	return &e, nil
}

// AddDeny 加入黑名单；所有者自身不可加入（由 handler 校验）。重复加入幂等。
func (s *Store) AddDeny(ctx context.Context, capabilityID, userID string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO capability_denylist (capability_id, user_id, created_at) VALUES (?,?,?)`,
			capabilityID, userID, fmtTime(now())); err != nil {
			return err
		}
		// 黑名单优先：加入黑名单时同时从白名单移除不是必须的（黑名单本身优先），
		// 但保留两个列表中的记录可让 UI 状态更直观，因此不做联动删除。
		return nil
	})
}

// RemoveDeny 移出黑名单。
func (s *Store) RemoveDeny(ctx context.Context, capabilityID, userID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM capability_denylist WHERE capability_id=? AND user_id=?`, capabilityID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddAllow 加入白名单，重复幂等。
func (s *Store) AddAllow(ctx context.Context, capabilityID, userID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO capability_allowlist (capability_id, user_id, created_at) VALUES (?,?,?)`,
		capabilityID, userID, fmtTime(now()))
	return err
}

// RemoveAllow 移出白名单。
func (s *Store) RemoveAllow(ctx context.Context, capabilityID, userID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM capability_allowlist WHERE capability_id=? AND user_id=?`, capabilityID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListDeny 列出黑名单（联查用户名用于展示）。
func (s *Store) ListDeny(ctx context.Context, capabilityID string) ([]*model.ListEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.capability_id, d.user_id, u.username, u.display_name, d.created_at
		FROM capability_denylist d JOIN users u ON u.id = d.user_id
		WHERE d.capability_id=? ORDER BY d.created_at DESC`, capabilityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.ListEntry
	for rows.Next() {
		e, err := scanListEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListAllow 列出白名单。
func (s *Store) ListAllow(ctx context.Context, capabilityID string) ([]*model.ListEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.capability_id, a.user_id, u.username, u.display_name, a.created_at
		FROM capability_allowlist a JOIN users u ON u.id = a.user_id
		WHERE a.capability_id=? ORDER BY a.created_at DESC`, capabilityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.ListEntry
	for rows.Next() {
		e, err := scanListEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// IsDenied 判断用户是否在黑名单。
func (s *Store) IsDenied(ctx context.Context, capabilityID, userID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM capability_denylist WHERE capability_id=? AND user_id=?`, capabilityID, userID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// IsAllowlisted 判断用户是否在白名单。
func (s *Store) IsAllowlisted(ctx context.Context, capabilityID, userID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM capability_allowlist WHERE capability_id=? AND user_id=?`, capabilityID, userID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
