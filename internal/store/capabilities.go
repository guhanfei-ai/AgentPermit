package store

import (
	"context"
	"database/sql"

	"agentpermit/internal/model"
)

const capColumns = `id, owner_user_id, name, slug, description, endpoint_url, http_method, api_path, spec_markdown, access_mode, status, latest_version, created_at, updated_at`

func scanCapability(row interface{ Scan(...any) error }) (*model.Capability, error) {
	var c model.Capability
	var createdAt, updatedAt string
	if err := row.Scan(&c.ID, &c.OwnerUserID, &c.Name, &c.Slug, &c.Description, &c.EndpointURL, &c.HTTPMethod, &c.APIPath, &c.SpecMarkdown, &c.AccessMode, &c.Status, &c.LatestVersion, &createdAt, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var err error
	if c.CreatedAt, err = parseTime(createdAt); err != nil {
		return nil, err
	}
	if c.UpdatedAt, err = parseTime(updatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

// CreateCapability 在事务中创建能力，按需保存初始 Service Token 凭证记录，
// 并把初始内容发布为 v1 且 latest 指向它（创建即发布，团队立即可见）。
// cred 可为 nil（纯内容能力）；凭证由调用方生成，原文只在响应中展示一次。
func (s *Store) CreateCapability(ctx context.Context, c *model.Capability, cred *model.ServiceCredential) error {
	c.CreatedAt = now()
	c.UpdatedAt = c.CreatedAt
	c.LatestVersion = 1
	return s.withTx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO capabilities (id, owner_user_id, name, slug, description, endpoint_url, http_method, api_path, spec_markdown, access_mode, status, latest_version, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			c.ID, c.OwnerUserID, c.Name, c.Slug, c.Description, c.EndpointURL, c.HTTPMethod, c.APIPath, c.SpecMarkdown, c.AccessMode, c.Status, c.LatestVersion, fmtTime(c.CreatedAt), fmtTime(c.UpdatedAt))
		if isUniqueViolation(err) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if cred != nil {
			cred.CreatedAt = c.CreatedAt
			_, err = tx.ExecContext(ctx, `INSERT INTO capability_service_credentials (capability_id, token_hash, token_hint, created_at) VALUES (?,?,?,?)`,
				cred.CapabilityID, cred.TokenHash, cred.TokenHint, fmtTime(cred.CreatedAt))
			if isUniqueViolation(err) {
				return ErrConflict
			}
			if err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO capability_versions (id, capability_id, version, name, description, endpoint_url, http_method, api_path, spec_markdown, published_by, published_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			NewID(), c.ID, 1, c.Name, c.Description, c.EndpointURL, c.HTTPMethod, c.APIPath, c.SpecMarkdown, c.OwnerUserID, fmtTime(c.CreatedAt))
		return err
	})
}

// GetCapabilityByID 查询能力。
func (s *Store) GetCapabilityByID(ctx context.Context, id string) (*model.Capability, error) {
	return scanCapability(s.db.QueryRowContext(ctx, `SELECT `+capColumns+` FROM capabilities WHERE id=?`, id))
}

// ListCapabilitiesByOwner 列出用户拥有的能力。
func (s *Store) ListCapabilitiesByOwner(ctx context.Context, ownerUserID string) ([]*model.Capability, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+capColumns+` FROM capabilities WHERE owner_user_id=? ORDER BY created_at DESC`, ownerUserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Capability
	for rows.Next() {
		c, err := scanCapability(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListAllCapabilities 列出全部能力（策略评估由上层完成，规模小可全量遍历）。
func (s *Store) ListAllCapabilities(ctx context.Context) ([]*model.Capability, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+capColumns+` FROM capabilities ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Capability
	for rows.Next() {
		c, err := scanCapability(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateCapability 编辑能力可变字段（slug 与所有者不可改）。
func (s *Store) UpdateCapability(ctx context.Context, id, ownerUserID string, c *model.Capability) error {
	res, err := s.db.ExecContext(ctx, `UPDATE capabilities SET name=?, description=?, endpoint_url=?, http_method=?, api_path=?, spec_markdown=?, access_mode=?, updated_at=?
		WHERE id=? AND owner_user_id=?`,
		c.Name, c.Description, c.EndpointURL, c.HTTPMethod, c.APIPath, c.SpecMarkdown, c.AccessMode, fmtTime(now()), id, ownerUserID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetCapabilityStatus 启用/停用能力（校验所有者）。
func (s *Store) SetCapabilityStatus(ctx context.Context, id, ownerUserID, status string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE capabilities SET status=?, updated_at=? WHERE id=? AND owner_user_id=?`,
		status, fmtTime(now()), id, ownerUserID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAccessMode 切换访问模式（校验所有者）。
func (s *Store) SetAccessMode(ctx context.Context, id, ownerUserID, mode string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE capabilities SET access_mode=?, updated_at=? WHERE id=? AND owner_user_id=?`,
		mode, fmtTime(now()), id, ownerUserID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
