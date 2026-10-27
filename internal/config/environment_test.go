package config

import "testing"

func TestClientEnvironmentKeepsExistingDefaults(t *testing.T) {
	for _, tc := range []struct{ environment, want string }{{"", "AGENTPERMIT_BASE_URL"}, {"test", "AGENTPERMIT_TEST_BASE_URL"}, {" blue_2 ", "AGENTPERMIT_BLUE_2_BASE_URL"}} {
		if got := (Config{Environment: tc.environment}).ClientEnvName("BASE_URL"); got != tc.want {
			t.Fatalf("环境前缀: %q != %q", got, tc.want)
		}
	}
}

func TestEnvironmentRejectsShellSyntax(t *testing.T) {
	for _, value := range []string{"bad-name", "$(whoami)", "a b", "1ENV"} {
		t.Run(value, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("非法变量名未拒绝")
				}
			}()
			normalizeEnvironment(value)
		})
	}
}

func TestExplicitDatabasePathDoesNotFallBack(t *testing.T) {
	t.Setenv("AGENTPERMIT_DB_PATH", DefaultDBPath)
	path, fallback := ResolveDBPath(DefaultDBPath)
	if path != DefaultDBPath || fallback {
		t.Fatal("显式配置必须优先")
	}
}
