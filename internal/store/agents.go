package store

import (
	"context"
	"database/sql"

	"agentpermit/internal/model"
)

const agentCredentialColumns = `id, owner_user_id, name, description, status, token_hash, token_hint, created_at, revoked_at`

func scanAgentCredential(row interface{ Scan(...any) error }) (*model.AgentCredential, error) {
	var a model.AgentCredential
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

// CreateAgentCredential 创建调用凭证记录，同一时间仅一枚当前有效 Token。
func (s *Store) CreateAgentCredential(ctx context.Context, a *model.AgentCredential) error {
	a.CreatedAt = now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO agents (id, owner_user_id, name, description, status, token_hash, token_hint, created_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		a.ID, a.OwnerUserID, a.Name, a.Description, a.Status, a.TokenHash, a.TokenHint, fmtTime(a.CreatedAt))
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

// GetAgentCredentialByID 查询凭证记录。
func (s *Store) GetAgentCredentialByID(ctx context.Context, id string) (*model.AgentCredential, error) {
	return scanAgentCredential(s.db.QueryRowContext(ctx, `SELECT `+agentCredentialColumns+` FROM agents WHERE id=?`, id))
}

// GetAgentCredentialByTokenHash 按 Token 摘要查询（Agent API 认证路径）。
func (s *Store) GetAgentCredentialByTokenHash(ctx context.Context, tokenHash string) (*model.AgentCredential, error) {
	return scanAgentCredential(s.db.QueryRowContext(ctx, `SELECT `+agentCredentialColumns+` FROM agents WHERE token_hash=?`, tokenHash))
}

// ListAgentCredentialsByOwner 列出账号名下的所有调用凭证。
func (s *Store) ListAgentCredentialsByOwner(ctx context.Context, ownerUserID string) ([]*model.AgentCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+agentCredentialColumns+` FROM agents WHERE owner_user_id=? ORDER BY created_at DESC`, ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AgentCredential
	for rows.Next() {
		a, err := scanAgentCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RevokeAgentCredential 撤销一条凭证记录（校验所有者），旧 Token 立即失效。
func (s *Store) RevokeAgentCredential(ctx context.Context, credentialID, ownerUserID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET status='revoked', revoked_at=? WHERE id=? AND owner_user_id=? AND status='active'`,
		fmtTime(now()), credentialID, ownerUserID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RotateAgentCredentialToken 在事务中轮换 Token（保留记录 ID 与限制），旧 Token 立即失效。
func (s *Store) RotateAgentCredentialToken(ctx context.Context, credentialID, ownerUserID, newTokenHash, newHint string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE agents SET token_hash=?, token_hint=? WHERE id=? AND owner_user_id=? AND status='active'`,
			newTokenHash, newHint, credentialID, ownerUserID)
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
