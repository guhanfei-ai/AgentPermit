package handler

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"agentpermit/internal/auth"
)

func TestProfilePasswordChangeRevokesSessions(t *testing.T) {
	e := newTestEnv(t)
	u := e.seedUser("profile_user", "个人用户")
	first := newHTTPClient(t, e.ts.URL)
	second := newHTTPClient(t, e.ts.URL)
	first.loginViaWeb(u.Username, testPassword)
	second.loginViaWeb(u.Username, testPassword)

	if !strings.Contains(first.getBody("/"), `href="/profile"`) {
		t.Fatal("我的菜单缺少个人资料入口")
	}
	first.refreshCSRF("/profile")
	if body := first.getBody("/profile"); !containsAll(body, "个人资料", u.Username, u.DisplayName, "修改登录密码") {
		t.Fatal("个人资料页缺少账号信息或改密表单")
	}

	originalHash := u.PasswordHash
	resp, _ := first.postForm("/profile/password", url.Values{
		"current_password": {"wrong-password"},
		"password":         {"newPassword456"},
		"password_confirm": {"newPassword456"},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/profile" {
		t.Fatalf("当前密码错误应返回个人资料页，得到 %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	got, err := e.st.GetUserByID(e.ctx, u.ID)
	if err != nil || got.PasswordHash != originalHash {
		t.Fatal("当前密码错误不应修改密码")
	}

	resp, _ = first.postForm("/profile/password", url.Values{
		"current_password": {testPassword},
		"password":         {"newPassword456"},
		"password_confirm": {"differentPassword"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("确认密码不一致应拒绝，得到 %d", resp.StatusCode)
	}
	got, err = e.st.GetUserByID(e.ctx, u.ID)
	if err != nil || got.PasswordHash != originalHash {
		t.Fatal("确认密码不一致不应修改密码")
	}

	const newPassword = "newPassword456"
	resp, _ = first.postForm("/profile/password", url.Values{
		"current_password": {testPassword},
		"password":         {newPassword},
		"password_confirm": {newPassword},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("改密成功应跳转登录页，得到 %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	got, err = e.st.GetUserByID(e.ctx, u.ID)
	if err != nil || !auth.CheckPassword(got.PasswordHash, newPassword) || auth.CheckPassword(got.PasswordHash, testPassword) {
		t.Fatal("密码哈希未按新密码更新")
	}
	for name, client := range map[string]*httpClient{"当前会话": first, "其他会话": second} {
		if resp := client.get("/"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
			t.Fatalf("%s改密后仍有效: %d %s", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	oldLogin := newHTTPClient(t, e.ts.URL)
	oldLogin.refreshCSRF("/login")
	resp, _ = oldLogin.postForm("/login", url.Values{"username": {u.Username}, "password": {testPassword}})
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatal("旧密码改密后仍能登录")
	}
	newLogin := newHTTPClient(t, e.ts.URL)
	newLogin.loginViaWeb(u.Username, newPassword)
}

func TestProfileRequiresLoginAndPasswordBoundaries(t *testing.T) {
	e := newTestEnv(t)
	anonymous := newHTTPClient(t, e.ts.URL)
	if resp := anonymous.get("/profile"); resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Fatalf("匿名访问个人资料应跳转登录，得到 %d", resp.StatusCode)
	}

	for _, tc := range []struct {
		password string
		confirm  string
		valid    bool
	}{
		{password: "12345678", confirm: "12345678", valid: true},
		{password: strings.Repeat("p", 72), confirm: strings.Repeat("p", 72), valid: true},
		{password: "123", confirm: "123"},
		{password: strings.Repeat("p", 73), confirm: strings.Repeat("p", 73)},
		{password: "1234", confirm: "1235"},
	} {
		if msg := validateNewPassword(tc.password, tc.confirm); (msg == "") != tc.valid {
			t.Fatalf("密码边界校验不符合预期: len=%d valid=%v msg=%q", len(tc.password), tc.valid, msg)
		}
	}
}
