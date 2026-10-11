-- 初始 schema：用户、会话、Agent、能力、黑白名单、服务凭证、审计。
-- 时间统一存储为 UTC RFC3339 文本。

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user'  CHECK (role IN ('user', 'admin')),
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS agents (
    id            TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    token_hash    TEXT NOT NULL UNIQUE,
    token_hint    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    revoked_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_agents_owner ON agents(owner_user_id);

CREATE TABLE IF NOT EXISTS capabilities (
    id            TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    slug          TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL DEFAULT '',
    endpoint_url  TEXT NOT NULL,
    http_method   TEXT NOT NULL DEFAULT 'GET',
    api_path      TEXT NOT NULL,
    spec_markdown TEXT NOT NULL DEFAULT '',
    access_mode   TEXT NOT NULL DEFAULT 'team' CHECK (access_mode IN ('team', 'allowlist')),
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capabilities_owner ON capabilities(owner_user_id);

CREATE TABLE IF NOT EXISTS capability_denylist (
    capability_id TEXT NOT NULL REFERENCES capabilities(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL,
    PRIMARY KEY (capability_id, user_id)
);

CREATE TABLE IF NOT EXISTS capability_allowlist (
    capability_id TEXT NOT NULL REFERENCES capabilities(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL,
    PRIMARY KEY (capability_id, user_id)
);

CREATE TABLE IF NOT EXISTS capability_service_credentials (
    capability_id TEXT PRIMARY KEY REFERENCES capabilities(id),
    token_hash    TEXT NOT NULL UNIQUE,
    token_hint    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    rotated_at    TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at     TEXT NOT NULL,
    event          TEXT NOT NULL,
    actor_user_id  TEXT,
    agent_id       TEXT,
    capability_id  TEXT,
    subject_user_id TEXT,
    outcome        TEXT NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'failure')),
    reason         TEXT NOT NULL DEFAULT '',
    request_id     TEXT NOT NULL DEFAULT '',
    detail         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_capability ON audit_logs(capability_id);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_logs(subject_user_id);
