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
	}
	base, err := template.New("base").Funcs(funcs).ParseFS(files, "templates/base.gohtml")
	if err != nil {
		return nil, fmt.Errorf("解析 base 模板失败: %w", err)
	}
	entries, err := fs.Glob(files, "templates/*.gohtml")
	if err != nil {
		return nil, err
	}
	out := map[string]*template.Template{}
	for _, name := range entries {
		if strings.HasSuffix(name, "base.gohtml") {
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
