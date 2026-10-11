// Package auth 提供密码哈希、高熵 Token 生成与会话 Cookie 辅助。
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// Token 前缀，便于区分用途，防止凭证串用。
// 更名前签发的旧前缀（aad_agent_ / aad_service_ / aad_session_）凭证仍可验证：
// 验证只按 SHA-256 摘要查库，不检查前缀。新签发一律使用 ap_ 前缀。
const (
	AgentTokenPrefix   = "ap_agent_"
	ServiceTokenPrefix = "ap_service_"
	SessionTokenPrefix = "ap_session_"

	// 旧前缀仅用于识别与展示，不参与验证。
	LegacyAgentTokenPrefix   = "aad_agent_"
	LegacyServiceTokenPrefix = "aad_service_"
)

// HashPassword 使用 bcrypt 哈希真人密码（绝不使用 SHA-256 存密码）。
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword 校验密码。
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// NewToken 生成带前缀的高熵随机 Token（256 bit 随机熵）。
// 返回：原文（仅展示一次）、SHA-256 摘要（入库索引）、提示串（前缀+尾4字符，用于列表识别）。
func NewToken(prefix string) (token, hash, hint string) {
	raw := make([]byte, 32) // 256 bit
	if _, err := rand.Read(raw); err != nil {
		panic("crypto/rand 失败: " + err.Error())
	}
	token = prefix + base64.RawURLEncoding.EncodeToString(raw)
	hash = HashToken(token)
	hint = prefix + "…" + token[len(token)-4:]
	return
}

// HashToken 计算凭证摘要。高熵随机 Token 使用 SHA-256 即可安全索引。
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewRandomHex 生成 n 字节随机数的 hex 表示（Session Token、CSRF Token 用）。
func NewRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 失败: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// EqualSecret 常数时间比较两个字符串（CSRF 校验用）。
func EqualSecret(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
