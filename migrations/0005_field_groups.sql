-- 服务登记（Server登记）下的能力契约变量编组。
-- 一个 Server 可挂多个编组；临时授信引用编组并保存签发时的定义快照与申报值。
-- 兼容说明：temporary_grants 旧数据 group_* 为空，按“未申报编组”继续核验。
CREATE TABLE server_field_groups (
 id TEXT PRIMARY KEY,
 server_id TEXT NOT NULL REFERENCES trusted_servers(id),
 name TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '',
 definition TEXT NOT NULL,
 created_by TEXT NOT NULL REFERENCES users(id),
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 UNIQUE(server_id, name)
);
CREATE INDEX server_field_groups_server ON server_field_groups(server_id);
ALTER TABLE temporary_grants ADD COLUMN group_id TEXT REFERENCES server_field_groups(id);
ALTER TABLE temporary_grants ADD COLUMN group_values TEXT NOT NULL DEFAULT '';
ALTER TABLE temporary_grants ADD COLUMN group_snapshot TEXT NOT NULL DEFAULT '';
