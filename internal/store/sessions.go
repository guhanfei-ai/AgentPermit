package store

import (
	"context"
	"database/sql"
	"time"

	"agentpermit/internal/model"
)

// CreateSession 插入新会话，仅保存 Token 摘要。
func (s *Store) CreateSession(ctx context.Context, tokenHash, userID, csrfToken string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at) VALUES (?,?,?,?,?)`,
		tokenHash, userID, csrfToken, fmtTime(now()), fmtTime(expiresAt))
	return err
}

// GetSessionByTokenHash 查询会话。
func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	var sess model.Session
	var createdAt, expiresAt string
	var revokedAt sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash, user_id, csrf_token, created_at, expires_at, revoked_at FROM sessions WHERE token_hash=?`,
		tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &sess.CSRFToken, &createdAt, &expiresAt, &revokedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if sess.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if sess.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return nil, err
	}
	if sess.RevokedAt, err = parseTimePtr(revokedAt); err != nil {
		return nil, err
	}
	return &sess, nil
}

// RevokeSession 撤销会话（退出登录）。
func (s *Store) RevokeSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at=? WHERE token_hash=?`, fmtTime(now()), tokenHash)
	return err
}

// RevokeSessionsForUser 撤销某用户全部会话（用户被禁用时调用）。
func (s *Store) RevokeSessionsForUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`, fmtTime(now()), userID)
	return err
}

// DeleteExpiredSessions 清理过期会话（可选维护操作）。
func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, fmtTime(now()))
	return err
}
