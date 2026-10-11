package store

import (
	"context"
	"database/sql"
	"errors"

	"agentpermit/internal/model"
)

const capVersionColumns = `v.id, v.capability_id, v.version, v.name, v.description, v.endpoint_url, v.http_method, v.api_path, v.spec_markdown, v.published_by, v.published_at, COALESCE(u.username,'')`

const capVersionFrom = ` FROM capability_versions v
	LEFT JOIN users u ON u.id = v.published_by `

func scanCapabilityVersion(row interface{ Scan(...any) error }) (*model.CapabilityVersion, error) {
	var v model.CapabilityVersion
	var publishedAt string
	if err := row.Scan(&v.ID, &v.CapabilityID, &v.Version, &v.Name, &v.Description, &v.EndpointURL, &v.HTTPMethod, &v.APIPath, &v.SpecMarkdown, &v.PublishedBy, &publishedAt, &v.PublishedByUsername); err != nil {
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

// PublishCapability 把能力的当前草稿（capabilities 可编辑字段）发布为下一个不可变版本，
// 并把 latest 标记指向它。调用方需先完成所有者校验。
func (s *Store) PublishCapability(ctx context.Context, capabilityID string) (*model.CapabilityVersion, error) {
	var out *model.CapabilityVersion
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var c model.Capability
		var createdAt, updatedAt string
		if err := tx.QueryRowContext(ctx, `SELECT `+capColumns+` FROM capabilities WHERE id=?`, capabilityID).
			Scan(&c.ID, &c.OwnerUserID, &c.Name, &c.Slug, &c.Description, &c.EndpointURL, &c.HTTPMethod, &c.APIPath, &c.SpecMarkdown, &c.AccessMode, &c.Status, &c.LatestVersion, &createdAt, &updatedAt); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		var maxVer int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM capability_versions WHERE capability_id=?`, capabilityID).Scan(&maxVer); err != nil {
			return err
		}
		ts := fmtTime(now())
		v := &model.CapabilityVersion{
			ID: NewID(), CapabilityID: c.ID, Version: maxVer + 1,
			Name: c.Name, Description: c.Description,
			EndpointURL: c.EndpointURL, HTTPMethod: c.HTTPMethod, APIPath: c.APIPath,
			SpecMarkdown: c.SpecMarkdown, PublishedBy: c.OwnerUserID,
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO capability_versions (id, capability_id, version, name, description, endpoint_url, http_method, api_path, spec_markdown, published_by, published_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			v.ID, v.CapabilityID, v.Version, v.Name, v.Description, v.EndpointURL, v.HTTPMethod, v.APIPath, v.SpecMarkdown, v.PublishedBy, ts); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE capabilities SET latest_version=?, updated_at=? WHERE id=?`,
			v.Version, ts, capabilityID); err != nil {
			return err
		}
		out = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetCapabilityLatest 移动能力的 latest 标记到任意已发布版本（回滚）。
// 调用方需先完成所有者校验。
func (s *Store) SetCapabilityLatest(ctx context.Context, capabilityID string, version int) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM capability_versions WHERE capability_id=? AND version=?`, capabilityID, version).Scan(&one); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE capabilities SET latest_version=?, updated_at=? WHERE id=?`,
			version, fmtTime(now()), capabilityID)
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

// GetCapabilityLatestSnapshot 读取能力 latest 指向的发布快照；尚未发布时返回 ErrNotFound。
func (s *Store) GetCapabilityLatestSnapshot(ctx context.Context, capabilityID string) (*model.CapabilityVersion, error) {
	return scanCapabilityVersion(s.db.QueryRowContext(ctx, `SELECT `+capVersionColumns+capVersionFrom+`
		WHERE v.capability_id=? AND v.version=(SELECT latest_version FROM capabilities WHERE id=?)`, capabilityID, capabilityID))
}

// ListCapabilityVersions 列出能力全部已发布版本，新版本在前。
func (s *Store) ListCapabilityVersions(ctx context.Context, capabilityID string) ([]*model.CapabilityVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+capVersionColumns+capVersionFrom+`
		WHERE v.capability_id=? ORDER BY v.version DESC`, capabilityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.CapabilityVersion
	for rows.Next() {
		v, err := scanCapabilityVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
