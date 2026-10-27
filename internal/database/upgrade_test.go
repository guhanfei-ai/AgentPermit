package database

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"agentpermit/migrations"
)

// 用升级前的真实 schema 写入数据，再应用新增迁移，验证保留能力与审计关联。
func TestServiceTrustUpgradePreservesCapabilities(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "upgrade.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA foreign_keys=ON; CREATE TABLE schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"0001_init.sql", "0002_collab_workspace.sql", "0003_capability_versions.sql"} {
		body, err := migrations.FS.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(string(body)); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`INSERT INTO schema_migrations VALUES (?, '2026-01-01T00:00:00Z')`, strings.TrimSuffix(file, ".sql")); err != nil {
			t.Fatal(err)
		}
	}
	fixtures := []string{
		`INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at) VALUES ('owner','owner','测试用户','fixture-hash','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')`,
		`INSERT INTO agents(id,owner_user_id,name,token_hash,created_at) VALUES ('agent','owner','测试凭证','agent-hash','2026-01-01T00:00:00Z')`,
		`INSERT INTO capabilities(id,owner_user_id,name,slug,endpoint_url,api_path,created_at,updated_at,latest_version) VALUES ('cap','owner','测试能力','test-cap','https://service.example.test','/read','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',1)`,
		`INSERT INTO capability_versions(id,capability_id,version,name,published_by,published_at) VALUES ('version','cap',1,'发布快照','owner','2026-01-01T00:00:00Z')`,
		`INSERT INTO capability_allowlist VALUES ('cap','owner','2026-01-01T00:00:00Z')`,
		`INSERT INTO capability_denylist VALUES ('cap','owner','2026-01-01T00:00:00Z')`,
		`INSERT INTO capability_service_credentials(capability_id,token_hash,created_at) VALUES ('cap','service-hash','2026-01-01T00:00:00Z')`,
		`INSERT INTO audit_logs(created_at,event,capability_id,agent_id) VALUES ('2026-01-01T00:00:00Z','authorize_allowed','cap','agent')`,
	}
	for _, query := range fixtures {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := Migrate(db); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"users", "agents", "capabilities", "capability_versions", "capability_allowlist", "capability_denylist", "capability_service_credentials"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s 存量数据丢失: %d %v", table, count, err)
		}
	}
	var capability, credential string
	if err := db.QueryRow(`SELECT capability_id,agent_id FROM audit_logs`).Scan(&capability, &credential); err != nil || capability != "cap" || credential != "agent" {
		t.Fatalf("审计关联丢失: %v", err)
	}
	for _, table := range []string{"trusted_servers", "temporary_grants", "server_field_groups", "work_bans", "holiday_plans"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("新表应为空: %s %d %v", table, count, err)
		}
	}
	var hash string
	if err := db.QueryRow(`SELECT holiday_unlock_password_hash FROM security_settings`).Scan(&hash); err != nil || hash != "" {
		t.Fatalf("不得设置默认解锁密码: %v", err)
	}
}
