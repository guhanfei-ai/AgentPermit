package handler

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"agentpermit/internal/model"
)

func (s *Server) dashboardData(r *http.Request) (*model.DashboardSnapshot, error) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	duration, buckets := 24*time.Hour, 12
	switch period {
	case "24h":
	case "7d":
		duration, buckets = 7*24*time.Hour, 7
	case "30d":
		duration, buckets = 30*24*time.Hour, 15
	default:
		return nil, fmt.Errorf("invalid period")
	}
	u := userFrom(r.Context())
	now := time.Now().UTC()
	// 审计时间精度为秒，右边界取下一秒，包含本秒内已经写入的事件。
	end := now.Truncate(time.Second).Add(time.Second)
	data, err := s.store.Dashboard(r.Context(), u.ID, u.IsAdmin(), end.Add(-duration), end, buckets)
	if err != nil {
		return nil, err
	}
	data.Period, data.GeneratedAt = period, now
	data.Scope = "我的数据"
	if u.IsAdmin() {
		data.Scope = "全局数据"
	}
	data.Runtime = s.metrics.snapshot(u.ID, u.IsAdmin())
	return data, nil
}

func validDashboardPeriod(r *http.Request) bool {
	p := r.URL.Query().Get("period")
	return p == "" || p == "24h" || p == "7d" || p == "30d"
}
func (s *Server) pageDashboard(w http.ResponseWriter, r *http.Request) {
	if !validDashboardPeriod(r) {
		s.renderError(w, r, http.StatusBadRequest, "请选择有效的统计时间范围。")
		return
	}
	data, err := s.dashboardData(r)
	if err != nil {
		s.logger.Error("查询首页统计失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "统计暂时不可用，请稍后刷新。")
		return
	}
	raw, err := json.Marshal(data)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "统计暂时不可用。")
		return
	}
	rate := "—"
	if data.ApprovalRate != nil {
		rate = fmt.Sprintf("%.1f%%", *data.ApprovalRate)
	}
	latency := "—"
	if data.Runtime.AverageMS != nil {
		latency = fmt.Sprintf("%.1f", *data.Runtime.AverageMS)
	}
	w.Header().Set("Cache-Control", "no-store")
	s.renderPage(w, r, http.StatusOK, "dashboard", "运行总览", "dashboard", map[string]any{
		"Stats": data, "Rate": rate, "Latency": latency,
		// json.Marshal 默认转义 <、>、&，因此不能用资源名称闭合 script 标签。
		"InitialJSON": template.JS(raw),
	})
}
func (s *Server) pageDashboardStats(w http.ResponseWriter, r *http.Request) {
	if !validDashboardPeriod(r) {
		s.jsonError(w, r, http.StatusBadRequest, "invalid_request", "请选择有效的统计时间范围")
		return
	}
	data, err := s.dashboardData(r)
	if err != nil {
		s.logger.Error("刷新首页统计失败", "err", err)
		s.jsonError(w, r, http.StatusInternalServerError, "internal", "统计暂时不可用")
		return
	}
	writeJSON(w, r, http.StatusOK, data)
}
