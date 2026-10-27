CREATE TABLE trusted_servers (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('MCP','Server','Nginx','其他')),
 description TEXT NOT NULL DEFAULT '',
 environment TEXT NOT NULL,
 origin TEXT NOT NULL,
 owner_user_id TEXT NOT NULL REFERENCES users(id),
 status TEXT NOT NULL CHECK(status IN ('active','disabled')),
 visibility TEXT NOT NULL CHECK(visibility IN ('public','admin')),
 token_hash TEXT NOT NULL UNIQUE,
 token_hint TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 UNIQUE(origin, environment)
);
CREATE TABLE temporary_grants (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id),
 credential_id TEXT NOT NULL REFERENCES agents(id),
 server_id TEXT NOT NULL REFERENCES trusted_servers(id),
 parent_token_hash TEXT NOT NULL,
 target_origin TEXT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE,
 token_hint TEXT NOT NULL,
 issued_by TEXT NOT NULL REFERENCES users(id),
 issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
 revoked_at INTEGER NOT NULL DEFAULT 0,
 revoked_by TEXT REFERENCES users(id),
 last_checked_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX temporary_grants_owner ON temporary_grants(user_id, issued_at DESC);
CREATE INDEX temporary_grants_server ON temporary_grants(server_id, issued_at DESC);
CREATE TABLE work_bans (
 id TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('person','credential','condition')),
 name TEXT NOT NULL,
 user_id TEXT REFERENCES users(id),
 credential_id TEXT REFERENCES agents(id),
 server_id TEXT REFERENCES trusted_servers(id),
 environment TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL,
 created_by TEXT NOT NULL REFERENCES users(id),
 starts_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL DEFAULT 0,
 released_at INTEGER NOT NULL DEFAULT 0,
 released_by TEXT REFERENCES users(id),
 CHECK(expires_at = 0 OR expires_at > starts_at),
 CHECK(kind != 'person' OR user_id IS NOT NULL),
 CHECK(kind != 'credential' OR credential_id IS NOT NULL)
);
CREATE INDEX work_bans_active ON work_bans(released_at, starts_at, expires_at);
CREATE TABLE holiday_plans (
 id TEXT PRIMARY KEY,
 created_by TEXT NOT NULL REFERENCES users(id),
 reason TEXT NOT NULL,
 trigger_at INTEGER NOT NULL,
 lock_at INTEGER NOT NULL CHECK(lock_at = trigger_at + 10),
 ends_at INTEGER NOT NULL CHECK(ends_at > lock_at),
 unlocked_at INTEGER NOT NULL DEFAULT 0,
 unlocked_by TEXT REFERENCES users(id),
 observed_state TEXT NOT NULL DEFAULT 'scheduled'
);
