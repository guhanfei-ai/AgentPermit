package store

import (
	"context"
	"database/sql"
	"errors"

	"agentpermit/internal/model"
)

const threadColumns = `t.id, t.project_id, t.title, t.status, t.created_by, t.floor_count, t.closed_at, t.closed_by, t.created_at, t.updated_at,
	COALESCE(u.username,''), COALESCE(u.display_name,''),
	p.slug, p.name, p.status,
	(SELECT MAX(f.created_at) FROM floors f WHERE f.thread_id = t.id)`

const threadFrom = ` FROM threads t
	LEFT JOIN users u ON u.id = t.created_by
	JOIN projects p ON p.id = t.project_id `

func scanThread(row interface{ Scan(...any) error }) (*model.Thread, error) {
	var t model.Thread
	var createdAt, updatedAt string
	var closedAt sql.NullString
	var closedBy sql.NullString
	var lastFloorAt sql.NullString
	if err := row.Scan(&t.ID, &t.ProjectID, &t.Title, &t.Status, &t.CreatedBy, &t.FloorCount, &closedAt, &closedBy, &createdAt, &updatedAt,
		&t.CreatedByUsername, &t.CreatedByDisplay, &t.ProjectSlug, &t.ProjectName, &t.ProjectStatus, &lastFloorAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if t.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if t.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	if t.ClosedAt, err = parseTimePtr(closedAt); err != nil {
		return nil, err
	}
	t.ClosedBy = closedBy.String
	if lastFloorAt.Valid && lastFloorAt.String != "" {
		if t.LastFloorAt, err = parseTime(lastFloorAt.String); err != nil {
			return nil, err
		}
	}
	return &t, nil
}

// CreateThread 由真人创建帖子：首帖（1 楼）与线程在同一事务写入。
func (s *Store) CreateThread(ctx context.Context, t *model.Thread, firstFloorBody string) error {
	t.CreatedAt = now()
	t.UpdatedAt = t.CreatedAt
	t.FloorCount = 1
	first := &model.Floor{
		ID:           NewID(),
		ThreadID:     t.ID,
		FloorNo:      1,
		AuthorUserID: t.CreatedBy,
		Body:         firstFloorBody,
		CreatedAt:    t.CreatedAt,
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		// 归档频道不可新建帖子
		var projectStatus string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM projects WHERE id=?`, t.ProjectID).Scan(&projectStatus); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if projectStatus != model.ProjectStatusActive {
			return ErrProjectArchived
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO threads (id, project_id, title, status, created_by, floor_count, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?)`,
			t.ID, t.ProjectID, t.Title, t.Status, t.CreatedBy, t.FloorCount, fmtTime(t.CreatedAt), fmtTime(t.UpdatedAt)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO floors (id, thread_id, floor_no, author_user_id, agent_id, body, created_at)
			VALUES (?,?,?,?,?,?,?)`,
			first.ID, first.ThreadID, first.FloorNo, first.AuthorUserID, nil, first.Body, fmtTime(first.CreatedAt))
		if err != nil {
			return err
		}
		// 频道 updated_at 联动，AI聊天广场按最近活跃排序
		_, err = tx.ExecContext(ctx, `UPDATE projects SET updated_at=? WHERE id=?`, fmtTime(t.CreatedAt), t.ProjectID)
		return err
	})
}

// GetThreadByID 查询帖子（含频道状态等联查字段）。
func (s *Store) GetThreadByID(ctx context.Context, id string) (*model.Thread, error) {
	return scanThread(s.db.QueryRowContext(ctx, `SELECT `+threadColumns+threadFrom+` WHERE t.id=?`, id))
}

// ListThreadsByProject 列出频道下的帖子，最近活跃在前。
func (s *Store) ListThreadsByProject(ctx context.Context, projectID string) ([]*model.Thread, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+threadColumns+threadFrom+` WHERE t.project_id=? ORDER BY t.updated_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Thread
	for rows.Next() {
		t, err := scanThread(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetThreadStatus 关闭/重开帖子（仅状态变更，楼层不动）。
func (s *Store) SetThreadStatus(ctx context.Context, id, status, byUserID string) error {
	var closedAt, closedBy any
	if status == model.ThreadStatusClosed {
		closedAt, closedBy = fmtTime(now()), byUserID
	}
	res, err := s.db.ExecContext(ctx, `UPDATE threads SET status=?, closed_at=?, closed_by=?, updated_at=? WHERE id=?`,
		status, closedAt, closedBy, fmtTime(now()), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const floorColumns = `f.id, f.thread_id, f.floor_no, f.author_user_id, COALESCE(f.agent_id,''), f.body, f.created_at,
	COALESCE(u.username,''), COALESCE(u.display_name,''), COALESCE(a.name,'')`

const floorFrom = ` FROM floors f
	LEFT JOIN users u ON u.id = f.author_user_id
	LEFT JOIN agents a ON a.id = f.agent_id `

func scanFloor(row interface{ Scan(...any) error }) (*model.Floor, error) {
	var f model.Floor
	var createdAt string
	if err := row.Scan(&f.ID, &f.ThreadID, &f.FloorNo, &f.AuthorUserID, &f.CredentialID, &f.Body, &createdAt,
		&f.AuthorUsername, &f.AuthorDisplayName, &f.CredentialName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if f.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	return &f, nil
}

// ListFloors 列出楼层：floor_no 大于 after、升序、最多 limit 条（limit<=0 用默认 200）。
// 配合 after 实现增量读取；返回值 + 是否还有更多由调用方根据 thread.FloorCount 判断。
func (s *Store) ListFloors(ctx context.Context, threadID string, after, limit int) ([]*model.Floor, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if after < 0 {
		after = 0
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+floorColumns+floorFrom+` WHERE f.thread_id=? AND f.floor_no>? ORDER BY f.floor_no ASC LIMIT ?`,
		threadID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Floor
	for rows.Next() {
		f, err := scanFloor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// AppendFloor 追加楼层：在单事务内复核频道状态、线程状态、禁言与容量后写入，
// 保证并发下的楼层号连续且不超上限。f.FloorNo 由本方法回填。
//
// 适用同一套校验：凭证请求传 credentialID；网页会话发言传空值（仅受账号级禁言约束）。
func (s *Store) AppendFloor(ctx context.Context, threadID string, authorUserID, credentialID, body string) (*model.Floor, error) {
	f := &model.Floor{ID: NewID(), ThreadID: threadID, AuthorUserID: authorUserID, CredentialID: credentialID, Body: body}
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		// 复核线程与频道状态（以事务内读到的最新值为准）
		var status, projectStatus string
		var floorCount int
		if err := tx.QueryRowContext(ctx, `SELECT t.status, p.status, t.floor_count
			FROM threads t JOIN projects p ON p.id = t.project_id WHERE t.id=?`, threadID).
			Scan(&status, &projectStatus, &floorCount); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if projectStatus != model.ProjectStatusActive {
			return ErrProjectArchived
		}
		if status != model.ThreadStatusOpen {
			return ErrThreadClosed
		}
		// 禁言复核（账号级覆盖所有调用凭证；网页会话发言只看账号级）
		q := `SELECT 1 FROM project_bans pb JOIN threads t ON t.project_id = pb.project_id
			WHERE t.id=? AND pb.user_id=? AND (pb.agent_id=''`
		args := []any{threadID, authorUserID}
		if credentialID != "" {
			q += ` OR pb.agent_id=?`
			args = append(args, credentialID)
		}
		q += `)`
		var one int
		if err := tx.QueryRowContext(ctx, q, args...).Scan(&one); err == nil {
			return ErrBanned
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		// 容量上限（含首帖）
		if floorCount >= model.MaxFloorsPerThread {
			return ErrThreadFull
		}
		f.FloorNo = floorCount + 1
		f.CreatedAt = now()
		if _, err := tx.ExecContext(ctx, `INSERT INTO floors (id, thread_id, floor_no, author_user_id, agent_id, body, created_at)
			VALUES (?,?,?,?,?,?,?)`,
			f.ID, f.ThreadID, f.FloorNo, f.AuthorUserID, nullStr(f.CredentialID), f.Body, fmtTime(f.CreatedAt)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE threads SET floor_count=?, updated_at=? WHERE id=?`,
			f.FloorNo, fmtTime(f.CreatedAt), threadID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE projects SET updated_at=? WHERE id=(SELECT project_id FROM threads WHERE id=?)`,
			fmtTime(f.CreatedAt), threadID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}
