package store

import (
	"context"
	"database/sql"
	"errors"

	"agentpermit/internal/model"
)

// GetProjectDoc 读取项目的 AGENTS.md 文档（草稿 + latest 标记）。项目创建时已初始化。
func (s *Store) GetProjectDoc(ctx context.Context, projectID string) (*model.ProjectDoc, error) {
	var d model.ProjectDoc
	var draftBy sql.NullString
	var draftAt, latestAt sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT project_id, draft_body, draft_updated_by, draft_updated_at, latest_version, latest_published_at
		FROM project_docs WHERE project_id=?`, projectID).
		Scan(&d.ProjectID, &d.DraftBody, &draftBy, &draftAt, &d.LatestVersion, &latestAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var perr error
	if d.DraftUpdatedAt, perr = parseTimePtr(draftAt); perr != nil {
		return nil, perr
	}
	if d.LatestPublishedAt, perr = parseTimePtr(latestAt); perr != nil {
		return nil, perr
	}
	d.DraftUpdatedBy = draftBy.String
	return &d, nil
}

// SaveDocDraft 保存 AGENTS.md 草稿（仅草稿，不影响对外生效的 latest 版本）。
func (s *Store) SaveDocDraft(ctx context.Context, projectID, body, byUserID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE project_docs SET draft_body=?, draft_updated_by=?, draft_updated_at=? WHERE project_id=?`,
		body, byUserID, fmtTime(now()), projectID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// PublishDoc 发布 AGENTS.md：把当前草稿快照为下一个不可变版本，并把 latest 指向它。
// 版本号 = 现有最大版本 + 1。
func (s *Store) PublishDoc(ctx context.Context, projectID, byUserID string) (int, error) {
	var version int
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var draft string
		var maxVer int
		if err := tx.QueryRowContext(ctx, `SELECT draft_body, COALESCE(MAX(version),0) FROM project_docs d
			LEFT JOIN project_doc_versions v ON v.project_id = d.project_id
			WHERE d.project_id=? GROUP BY d.project_id`, projectID).Scan(&draft, &maxVer); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		version = maxVer + 1
		ts := fmtTime(now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_doc_versions (project_id, version, body, published_by, published_at)
			VALUES (?,?,?,?,?)`, projectID, version, draft, byUserID, ts); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE project_docs SET latest_version=?, latest_published_at=? WHERE project_id=?`,
			version, ts, projectID)
		return err
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

// SetDocLatest 移动 latest 标记到任意已发布版本（可回指旧版本实现回滚）。
func (s *Store) SetDocLatest(ctx context.Context, projectID string, version int) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM project_doc_versions WHERE project_id=? AND version=?`, projectID, version).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE project_docs SET latest_version=?, latest_published_at=(SELECT published_at FROM project_doc_versions WHERE project_id=? AND version=?) WHERE project_id=?`,
			version, projectID, version, projectID)
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

// GetDocVersion 读取指定已发布版本。
func (s *Store) GetDocVersion(ctx context.Context, projectID string, version int) (*model.ProjectDocVersion, error) {
	return scanDocVersion(s.db.QueryRowContext(ctx, `SELECT `+docVersionColumns+` FROM project_doc_versions v
		LEFT JOIN users u ON u.id = v.published_by
		WHERE v.project_id=? AND v.version=?`, projectID, version))
}

// GetDocLatest 读取 latest 指向的版本内容；尚未发布时返回 ErrNotFound。
func (s *Store) GetDocLatest(ctx context.Context, projectID string) (*model.ProjectDocVersion, error) {
	return scanDocVersion(s.db.QueryRowContext(ctx, `SELECT `+docVersionColumns+` FROM project_doc_versions v
		LEFT JOIN users u ON u.id = v.published_by
		WHERE v.project_id=? AND v.version=(SELECT latest_version FROM project_docs WHERE project_id=?)`,
		projectID, projectID))
}

// ListDocVersions 列出全部已发布版本，新版本在前。
func (s *Store) ListDocVersions(ctx context.Context, projectID string) ([]*model.ProjectDocVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+docVersionColumns+` FROM project_doc_versions v
		LEFT JOIN users u ON u.id = v.published_by
		WHERE v.project_id=? ORDER BY v.version DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.ProjectDocVersion
	for rows.Next() {
		v, err := scanDocVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

const docVersionColumns = `v.project_id, v.version, v.body, v.published_by, v.published_at, COALESCE(u.username,'')`

func scanDocVersion(row interface{ Scan(...any) error }) (*model.ProjectDocVersion, error) {
	var v model.ProjectDocVersion
	var publishedAt string
	if err := row.Scan(&v.ProjectID, &v.Version, &v.Body, &v.PublishedBy, &publishedAt, &v.PublishedByUsername); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if v.PublishedAt, err = parseTime(publishedAt); err != nil {
		return nil, err
	}
	return &v, nil
}
