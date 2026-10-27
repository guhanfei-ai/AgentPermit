// Package web 内嵌全部模板与静态资源，服务端渲染使用。
package web

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"path/filepath"
	"strings"
	"time"
)

//go:embed templates/*.gohtml static/*
var files embed.FS

// 默认说明随二进制发布，不要求部署时拷贝额外文档。
//
//go:embed guide.md
var AgentGuide []byte

// Templates 解析 base 布局与每个页面模板，返回 页面名 → 模板。
// 页面模板只定义 "content"，导航等公共结构由 base 提供。
func Templates() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Local().Format("2006-01-02 15:04:05")
		},
		"navActive": func(cur, want string) string {
			if cur == want {
				return "active"
			}
			return ""
		},
		"trustTime": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.In(time.FixedZone("Asia/Shanghai", 28800)).Format("2006-01-02 15:04:05")
		},
		"trustInput": func(t time.Time) string {
			if t.IsZero() {
				return ""
			}
			return t.In(time.FixedZone("Asia/Shanghai", 28800)).Format("2006-01-02T15:04:05")
		},
		"trustReason": func(code string) string {
			labels := map[string]string{"": "可用", "holiday_lockdown": "节假日封网", "person_banned": "人员已封禁", "credential_banned": "AI凭证已封禁", "conditional_banned": "命中条件封禁", "grant_revoked": "已撤销", "grant_not_effective": "不在有效期内", "server_disabled": "Server已停用", "parent_credential_invalid": "原始凭证已失效或轮换", "grant_scope_mismatch": "接入范围已变更"}
			if value, ok := labels[code]; ok {
				return value
			}
			return code
		},
	}
	base, err := template.New("base").Funcs(funcs).ParseFS(files, "templates/base.gohtml", "templates/trust_shared.gohtml")
	if err != nil {
		return nil, fmt.Errorf("解析 base 模板失败: %w", err)
	}
	entries, err := fs.Glob(files, "templates/*.gohtml")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, name := range entries {
		if strings.HasSuffix(name, "base.gohtml") || strings.HasSuffix(name, "trust_shared.gohtml") {
			continue
		}
		t, err := template.Must(base.Clone()).ParseFS(files, name)
		if err != nil {
			return nil, fmt.Errorf("解析模板 %s 失败: %w", name, err)
		}
		out[strings.TrimSuffix(filepath.Base(name), ".gohtml")] = t
	}
	return out, nil
}

// Static 返回静态资源子文件系统。
func Static() (fs.FS, error) {
	return fs.Sub(files, "static")
}
