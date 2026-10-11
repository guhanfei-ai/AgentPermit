package store

import (
	"context"
	"database/sql"

	"agentpermit/internal/model"
)

const agentColumns = `id, owner_user_id, name, description, status, token_hash, token_hint, created_at, revoked_at`

func scanAgent(row interface{ Scan(...any) error }) (*model.Agent, error) {
	var a model.Agent
	var createdAt string
	var revokedAt sql.NullString
	if err := row.Scan(&a.ID, &a.OwnerUserID, &a.Name, &a.Description, &a.Status, &a.TokenHash, &a.TokenHint, &createdAt, &revokedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if a.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if a.RevokedAt, err = parseTimePtr(revokedAt); err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateAgent 创建 Agent，同一时间仅一枚当前有效 Token。
func (s *Store) CreateAgent(ctx context.Context, a *model.Agent) error {
	a.CreatedAt = now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO agents (id, owner_user_id, name, description, status, token_hash, token_hint, created_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		a.ID, a.OwnerUserID, a.Name, a.Description, a.Status, a.TokenHash, a.TokenHint, fmtTime(a.CreatedAt))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// GetAgentByID 查询 Agent。
func (s *Store) GetAgentByID(ctx context.Context, id string) (*model.Agent, error) {
	return scanAgent(s.db.QueryRowContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE id=?`, id))
}

// GetAgentByTokenHash 按 Token 摘要查询（Agent API 认证路径）。
func (s *Store) GetAgentByTokenHash(ctx context.Context, tokenHash string) (*model.Agent, error) {
	return scanAgent(s.db.QueryRowContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE token_hash=?`, tokenHash))
}

// ListAgentsByOwner 列出用户的所有 Agent。
func (s *Store) ListAgentsByOwner(ctx context.Context, ownerUserID string) ([]*model.Agent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE owner_user_id=? ORDER BY created_at DESC`, ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RevokeAgent 撤销 Agent（校验所有者），旧 Token 立即失效。
func (s *Store) RevokeAgent(ctx context.Context, agentID, ownerUserID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET status='revoked', revoked_at=? WHERE id=? AND owner_user_id=? AND status='active'`,
		fmtTime(now()), agentID, ownerUserID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RotateAgentToken 在事务中轮换 Agent Token，旧 Token 立即失效。
func (s *Store) RotateAgentToken(ctx context.Context, agentID, ownerUserID, newTokenHash, newHint string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE agents SET token_hash=?, token_hint=? WHERE id=? AND owner_user_id=? AND status='active'`,
			newTokenHash, newHint, agentID, ownerUserID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}
