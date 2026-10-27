package handler

import (
	"net/http"
	"testing"
)

// 分页必须真正生效，非法参数显式拒绝，省略参数保持旧客户端兼容。
func TestProjectsPagination(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("pager", "翻页人")
	_, token := e.seedCredential(u, "翻页Agent")

	// 3 个频道，覆盖多页场景
	seedProjectViaWeb(t, e, u, "pg-alpha")
	seedProjectViaWeb(t, e, u, "pg-beta")
	seedProjectViaWeb(t, e, u, "pg-gamma")

	// 不带参数：全量返回（兼容既有调用），total 正确且 has_more=false
	code, body := getJSON(t, e.ts.URL, "/api/v1/projects", token)
	if code != http.StatusOK || len(body["projects"].([]any)) != 3 ||
		body["total"].(float64) != 3 || body["has_more"] != false {
		t.Fatalf("无参数应返回全量: %d %v", code, body)
	}

	// limit=2：返回 2 条，has_more=true，next_offset=2
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects?limit=2", token)
	if code != http.StatusOK || len(body["projects"].([]any)) != 2 ||
		body["total"].(float64) != 3 || body["has_more"] != true || body["next_offset"].(float64) != 2 {
		t.Fatalf("limit=2 应分页: %d %v", code, body)
	}

	// limit=2&offset=2：尾页 1 条，has_more=false，next_offset=3（=total）
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects?limit=2&offset=2", token)
	if code != http.StatusOK || len(body["projects"].([]any)) != 1 ||
		body["has_more"] != false || body["next_offset"].(float64) != 3 {
		t.Fatalf("offset 翻页应生效: %d %v", code, body)
	}

	// 仅 offset（省略 limit）：跳过前 2 条返回剩余全部
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects?offset=2", token)
	if code != http.StatusOK || len(body["projects"].([]any)) != 1 || body["has_more"] != false {
		t.Fatalf("仅 offset 应跳过前 2 条: %d %v", code, body)
	}

	// offset 越过总数：空页而不是错误
	code, body = getJSON(t, e.ts.URL, "/api/v1/projects?limit=2&offset=99", token)
	if code != http.StatusOK || len(body["projects"].([]any)) != 0 ||
		body["total"].(float64) != 3 || body["has_more"] != false {
		t.Fatalf("offset 越界应返回空页: %d %v", code, body)
	}

	// 非法取值一律 422（覆盖边界值和格式错误）
	for _, q := range []string{
		"limit=0", "limit=-1", "limit=abc", "limit=1.5", "limit=201", "limit=",
		"offset=-1", "offset=abc", "offset=",
		"page=1",
	} {
		code, body = getJSON(t, e.ts.URL, "/api/v1/projects?"+q, token)
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("?%s 应 422: %d %v", q, code, body)
		}
	}

	// 分页校验不绕过凭证：未认证依然 401
	code, _ = getJSON(t, e.ts.URL, "/api/v1/projects?limit=1", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("未认证应 401: %d", code)
	}
}
