package config

import (
	"fmt"
	"regexp"
	"strings"
)

var environmentPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)

func normalizeEnvironment(value string) string {
	environment := strings.ToUpper(strings.TrimSpace(value))
	if environment != "" && !environmentPattern.MatchString(environment) {
		panic(fmt.Sprintf("AGENTPERMIT_ENV=%q 须以字母开头，只包含字母、数字或下划线，最多 32 位", value))
	}
	return environment
}

// 未配置环境时保留旧变量名；多实例可显式设置环境，避免客户端串用配置。
func (c Config) ClientEnvName(suffix string) string {
	if environment := normalizeEnvironment(c.Environment); environment != "" {
		return "AGENTPERMIT_" + environment + "_" + suffix
	}
	return "AGENTPERMIT_" + suffix
}
