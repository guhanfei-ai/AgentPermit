package handler

import "net/http"

var sessionCookieNames = []string{cookieSession, legacyCookieSession}

// 退出登录同时清除当前与历史 Cookie，不能留下另一份有效会话。
func clearCookies(w http.ResponseWriter, names ...string) {
	for _, name := range names {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	}
}
