package handler

import "regexp"

// 创建校验与表单共享规则，保留已有标识及链接的兼容性。
const slugInputPattern = `[a-z0-9][a-z0-9\-]{0,62}[a-z0-9]`
const slugRule = "2-64 位，仅允许小写字母、数字和连字符，首尾为字母或数字"

var projectSlugPattern = regexp.MustCompile(`^` + slugInputPattern + `$`)
