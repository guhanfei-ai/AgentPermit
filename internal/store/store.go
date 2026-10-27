// Package store 是基于 database/sql 的数据访问层，不引入 ORM。
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"agentpermit/internal/model"
)

// ErrNotFound 表示查询目标不存在。
var ErrNotFound = errors.New("record not found")

// ErrConflict 表示唯一约束冲突（用户名、slug 已存在等）。
var ErrConflict = errors.New("conflict")

// 帖子发言时的状态类错误（HTTP 层据此映射状态码）。
var (
	// ErrThreadClosed 帖子已关闭，只读。
	ErrThreadClosed = errors.New("thread closed")
	// ErrThreadFull 帖子已达楼数上限（含发帖时的 1 楼，共 5000 楼）。
	ErrThreadFull = errors.New("thread full")
	// ErrProjectArchived 频道已归档，只读。
	ErrProjectArchived = errors.New("project archived")
	// ErrBanned 发言者被频道禁言（账号级覆盖所有调用凭证，单凭证限制只作用于指定记录）。
	ErrBanned = errors.New("banned")
)

// Store 封装全部数据库访问。
type Store struct {
	db    *sql.DB
	clock func() time.Time
}

// New 创建 Store。
func New(db *sql.DB) *Store { return NewWithClock(db, time.Now) }

// NewWithClock 支持使用统一服务端时钟判定授信和封禁期限。
func NewWithClock(db *sql.DB, clock func() time.Time) *Store { return &Store{db: db, clock: clock} }

func (s *Store) Now() time.Time { return s.clock().UTC().Truncate(time.Second) }

// DB 暴露底层连接（仅供测试使用）。
func (s *Store) DB() *sql.DB { return s.db }

// ---- 通用辅助 ----

// NewID 生成 128 bit 随机 hex 标识。
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 失败: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// fmtTime 将时间统一转为 UTC RFC3339 存储。
func fmtTime(t time.Time) string {
	return t.UTC().Format(model.TimeLayout)
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(model.TimeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析时间 %q 失败: %w", s, err)
	}
	return t, nil
}

func parseTimePtr(s sql.NullString) (*time.Time, error) {
	if !s.Valid || s.String == "" {
		return nil, nil
	}
	t, err := parseTime(s.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// now 返回当前 UTC 时间。
func now() time.Time { return time.Now().UTC() }

// isUniqueViolation 判断 SQLite 唯一约束冲突。
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// withTx 在事务中执行 fn，出错回滚。
func (s *Store) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}
