package store

import (
	"context"
	"database/sql"

	"agentpermit/internal/model"
)

// GetServiceCredentialByTokenHash 按 Token 摘要查询能力服务凭证（授权接口认证路径）。
func (s *Store) GetServiceCredentialByTokenHash(ctx context.Context, tokenHash string) (*model.ServiceCredential, error) {
	var cred model.ServiceCredential
	var createdAt string
	var rotatedAt sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT capability_id, token_hash, token_hint, created_at, rotated_at FROM capability_service_credentials WHERE token_hash=?`,
		tokenHash).
		Scan(&cred.CapabilityID, &cred.TokenHash, &cred.TokenHint, &createdAt, &rotatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if cred.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if cred.RotatedAt, err = parseTimePtr(rotatedAt); err != nil {
		return nil, err
	}
	return &cred, nil
}

// GetServiceCredentialByCapability 查询能力当前凭证。
func (s *Store) GetServiceCredentialByCapability(ctx context.Context, capabilityID string) (*model.ServiceCredential, error) {
	var cred model.ServiceCredential
	var createdAt string
	var rotatedAt sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT capability_id, token_hash, token_hint, created_at, rotated_at FROM capability_service_credentials WHERE capability_id=?`,
		capabilityID).
		Scan(&cred.CapabilityID, &cred.TokenHash, &cred.TokenHint, &createdAt, &rotatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if cred.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if cred.RotatedAt, err = parseTimePtr(rotatedAt); err != nil {
		return nil, err
	}
	return &cred, nil
}

// RotateServiceToken 在事务中生成或轮换服务验证凭证，旧 Token 立即失效。
func (s *Store) RotateServiceToken(ctx context.Context, capabilityID, ownerUserID, newHash, newHint string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		// 校验能力归属，防止越权轮换他人凭证。
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT owner_user_id FROM capabilities WHERE id=?`, capabilityID).Scan(&owner)
		if err == sql.ErrNoRows || (err == nil && owner != ownerUserID) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ts := fmtTime(now())
		_, err = tx.ExecContext(ctx, `INSERT INTO capability_service_credentials (capability_id, token_hash, token_hint, created_at)
			VALUES (?,?,?,?) ON CONFLICT(capability_id) DO UPDATE SET
			token_hash=excluded.token_hash, token_hint=excluded.token_hint, rotated_at=excluded.created_at`,
			capabilityID, newHash, newHint, ts)
		return err
	})
}
