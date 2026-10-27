package handler

import (
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// publicAPIBaseURL 按当前访问入口生成调用方的 API 根地址。
// 代理转发头仅在连接来自显式配置的可信代理时使用。
func (s *Server) publicAPIBaseURL(r *http.Request, prefix string) string {
	scheme, host := "http", r.Host
	if r.TLS != nil {
		scheme = "https"
	}
	if s.isTrustedProxy(r.RemoteAddr) {
		if forwarded := firstForwarded(r.Header.Get("X-Forwarded-Proto")); forwarded == "http" || forwarded == "https" {
			scheme = forwarded
		}
		if forwarded := firstForwarded(r.Header.Get("X-Forwarded-Host")); validPublicHost(forwarded) {
			host = forwarded
		}
	}
	if !validPublicHost(host) {
		if fallback, err := url.Parse(s.cfg.BaseURL); err == nil && validPublicHost(fallback.Host) && (fallback.Scheme == "http" || fallback.Scheme == "https") {
			scheme, host = fallback.Scheme, fallback.Host
		} else {
			return prefix
		}
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: prefix}).String()
}

func (s *Server) isTrustedProxy(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, prefix := range s.cfg.TrustedProxies {
		if prefix.Contains(address.Unmap()) {
			return true
		}
	}
	return false
}

func firstForwarded(value string) string {
	return strings.TrimSpace(strings.SplitN(value, ",", 2)[0])
}

func validPublicHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "/\\?#@ \t\r\n") {
		return false
	}
	u, err := url.Parse("http://" + host)
	return err == nil && u.Host == host && u.Hostname() != ""
}
