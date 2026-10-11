// Package demoservice 是独立的演示业务服务：查询模拟机器配置。
// 它不参与平台内部逻辑，每次业务调用都实时回调平台授权接口（fail closed）。
package demoservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Machine 是模拟机器配置数据。
type Machine struct {
	ID     string `json:"machine_id"`
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
	Disk   string `json:"disk"`
	OS     string `json:"os"`
}

var machines = map[string]Machine{
	"machine-001": {ID: "machine-001", CPU: "8 cores", Memory: "32 GiB", Disk: "500 GiB", OS: "Ubuntu 22.04"},
	"machine-002": {ID: "machine-002", CPU: "16 cores", Memory: "64 GiB", Disk: "1 TiB", OS: "Rocky Linux 9"},
}

// authorizeResponse 平台授权接口的决策对象（只取本服务需要的字段）。
type authorizeResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// Service 演示机器服务。
type Service struct {
	baseURL      string
	serviceToken string
	client       *http.Client
	logger       *slog.Logger
}

// New 创建服务。baseURL 是平台地址，serviceToken 是能力所有者获取的服务验证凭证。
func New(baseURL, serviceToken string, logger *slog.Logger) *Service {
	return &Service{
		baseURL:      strings.TrimRight(baseURL, "/"),
		serviceToken: serviceToken,
		client:       &http.Client{Timeout: 5 * time.Second},
		logger:       logger,
	}
}

// Handler 返回路由。业务入口全部受授权保护；健康检查匿名但不暴露机器信息。
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /machines/{machine_id}/spec", s.machineSpec)
	return mux
}

// authorize 调用平台授权接口。任何网络错误、超时、非 200、解析失败一律视为“无法确认权限”，
// 返回 err，调用方必须 fail closed。
func (s *Service) authorize(ctx context.Context, agentToken string) (authorizeResponse, error) {
	body, _ := json.Marshal(map[string]string{"agent_token": agentToken})
	// 只构造必要请求，绝不原样转发调用者的 Header
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/api/v1/service/authorize", bytes.NewReader(body))
	if err != nil {
		return authorizeResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+s.serviceToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return authorizeResponse{}, fmt.Errorf("平台请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return authorizeResponse{}, fmt.Errorf("平台授权接口返回 %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return authorizeResponse{}, err
	}
	var decision authorizeResponse
	if err := json.Unmarshal(data, &decision); err != nil {
		return authorizeResponse{}, fmt.Errorf("解析授权响应失败: %w", err)
	}
	return decision, nil
}

func (s *Service) machineSpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	writeErr := func(status int, code, msg string) {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
	}

	agentToken := bearerToken(r)
	if agentToken == "" {
		writeErr(http.StatusUnauthorized, "unauthorized", "缺少 Agent Token")
		return
	}
	decision, err := s.authorize(r.Context(), agentToken)
	if err != nil {
		// 平台不可用或无法确认权限：fail closed，不返回机器信息
		s.logger.Error("授权校验失败，拒绝服务", "err", err)
		writeErr(http.StatusServiceUnavailable, "authorization_unavailable", "暂时无法验证访问权限，请稍后再试")
		return
	}
	if !decision.Allowed {
		// 凭证无效/撤销 → 401；身份有效但无权限 → 403
		if decision.Reason == "invalid_agent_token" || decision.Reason == "agent_revoked" {
			writeErr(http.StatusUnauthorized, "unauthorized", "Agent Token 无效或已撤销")
			return
		}
		writeErr(http.StatusForbidden, "forbidden", "无权访问该能力: "+decision.Reason)
		return
	}
	machineID := r.PathValue("machine_id")
	m, ok := machines[machineID]
	if !ok {
		// 机器不存在在授权成功后才返回 404
		writeErr(http.StatusNotFound, "machine_not_found", "机器不存在")
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(m)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
