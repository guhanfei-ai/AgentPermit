-- 能力内容版本：capabilities 现有可编辑字段成为「草稿」，
-- 每次发布把草稿快照为不可变的 capability_versions 记录，
-- latest_version 标记指向对外生效的已发布版本（可回指旧版本实现回滚）。

ALTER TABLE capabilities ADD COLUMN latest_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS capability_versions (
    id            TEXT PRIMARY KEY,
    capability_id TEXT NOT NULL REFERENCES capabilities(id),
    version       INTEGER NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    endpoint_url  TEXT NOT NULL DEFAULT '',
    http_method   TEXT NOT NULL DEFAULT 'GET',
    api_path      TEXT NOT NULL DEFAULT '',
    spec_markdown TEXT NOT NULL DEFAULT '',
    published_by  TEXT NOT NULL REFERENCES users(id),
    published_at  TEXT NOT NULL,
    UNIQUE (capability_id, version)
);
CREATE INDEX IF NOT EXISTS idx_capversions_capability ON capability_versions(capability_id);

-- 存量能力回填 v1 并设为 latest：升级前后 Agent 读到的内容一致，后续编辑进入草稿态。
INSERT INTO capability_versions (id, capability_id, version, name, description, endpoint_url, http_method, api_path, spec_markdown, published_by, published_at)
SELECT lower(hex(randomblob(16))), id, 1, name, description, endpoint_url, http_method, api_path, spec_markdown, owner_user_id, updated_at
FROM capabilities;

UPDATE capabilities SET latest_version = 1;
