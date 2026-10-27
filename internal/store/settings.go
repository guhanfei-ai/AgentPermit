package store

import (
	"context"
	"database/sql"
)

// GetHolidayUnlockPasswordHash 读取全局封网解锁密码的 bcrypt 哈希。
func (s *Store) GetHolidayUnlockPasswordHash(ctx context.Context) (string, error) {
	var hash string
	err := s.db.QueryRowContext(ctx, `SELECT holiday_unlock_password_hash FROM security_settings WHERE id=1`).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return hash, err
}

// UpdateHolidayUnlockPasswordHash 更新全局封网解锁密码的 bcrypt 哈希。
func (s *Store) UpdateHolidayUnlockPasswordHash(ctx context.Context, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE security_settings SET holiday_unlock_password_hash=?,updated_at=? WHERE id=1`, hash, fmtTime(s.Now()))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
