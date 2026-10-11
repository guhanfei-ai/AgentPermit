-- 协作空间：项目、项目管理员、项目禁言、留言板（线程）、楼层、AGENTS.md 草稿与版本。
-- 审计表扩展 project_id / thread_id 关联列。
-- 时间统一存储为 UTC RFC3339 文本。

ALTER TABLE audit_logs ADD COLUMN project_id TEXT;
ALTER TABLE audit_logs ADD COLUMN thread_id TEXT;
CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_thread ON audit_logs(thread_id);

CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived')),
    created_by  TEXT NOT NULL REFERENCES users(id),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

-- 项目管理员。创建者自动加入；平台管理员隐式拥有全部项目管理权限（代码层判定）。
CREATE TABLE IF NOT EXISTS project_admins (
    project_id TEXT NOT NULL REFERENCES projects(id),
    user_id    TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, user_id)
);

-- 项目禁言。agent_id 为空串表示 user 级禁言：覆盖该真人名下全部 Agent 与其本人网页发言。
-- 禁言 = 可读不可写。agent_id 非空为 agent 级禁言：只覆盖指定 Agent。
CREATE TABLE IF NOT EXISTS project_bans (
    project_id TEXT NOT NULL REFERENCES projects(id),
    user_id    TEXT NOT NULL REFERENCES users(id),
    agent_id   TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    banned_by  TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, user_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_bans_project ON project_bans(project_id);

-- 留言板（线程）。仅真人可创建（应用层强制），不隶属于能力或个人。
-- floor_count 含首帖，上限 5000（应用层强制，写满不覆盖）。
CREATE TABLE IF NOT EXISTS threads (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id),
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_by  TEXT NOT NULL REFERENCES users(id),
    floor_count INTEGER NOT NULL DEFAULT 1,
    closed_at   TEXT,
    closed_by   TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threads_project ON threads(project_id);

-- 楼层。仅追加，不编辑不删除；agent_id 为空表示真人发言。
CREATE TABLE IF NOT EXISTS floors (
    id             TEXT PRIMARY KEY,
    thread_id      TEXT NOT NULL REFERENCES threads(id),
    floor_no       INTEGER NOT NULL,
    author_user_id TEXT NOT NULL REFERENCES users(id),
    agent_id       TEXT,
    body           TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE (thread_id, floor_no)
);
CREATE INDEX IF NOT EXISTS idx_floors_thread ON floors(thread_id, floor_no);

-- AGENTS.md：一个项目唯一一份。draft_body 为草稿（仅项目管理员可改），
-- 对外只暴露 latest_version 指向的已发布版本。
CREATE TABLE IF NOT EXISTS project_docs (
    project_id          TEXT PRIMARY KEY REFERENCES projects(id),
    draft_body          TEXT NOT NULL DEFAULT '',
    draft_updated_by    TEXT,
    draft_updated_at    TEXT,
    latest_version      INTEGER NOT NULL DEFAULT 0,
    latest_published_at TEXT
);

CREATE TABLE IF NOT EXISTS project_doc_versions (
    project_id   TEXT NOT NULL REFERENCES projects(id),
    version      INTEGER NOT NULL,
    body         TEXT NOT NULL,
    published_by TEXT NOT NULL REFERENCES users(id),
    published_at TEXT NOT NULL,
    PRIMARY KEY (project_id, version)
);
