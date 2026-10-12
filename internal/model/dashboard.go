package model

import "time"

// DashboardSnapshot 仅包含当前账号可见的聚合数据，不包含凭证摘要或审计原文。
type DashboardSnapshot struct {
	Period            string              `json:"period"`
	Scope             string              `json:"scope"`
	GeneratedAt       time.Time           `json:"generated_at"`
	Authorizations    int64               `json:"authorizations"`
	Allowed           int64               `json:"allowed"`
	Denied            int64               `json:"denied"`
	Posts             int64               `json:"posts"`
	ActiveCredentials int64               `json:"active_credentials"`
	ApprovalRate      *float64            `json:"approval_rate"`
	Trend             []DashboardPoint    `json:"trend"`
	CapabilityRanking []DashboardRank     `json:"capability_ranking"`
	CredentialRanking []DashboardRank     `json:"credential_ranking"`
	Activity          []DashboardActivity `json:"activity"`
	Resources         DashboardResources  `json:"resources"`
	Runtime           DashboardRuntime    `json:"runtime"`
}

type DashboardPoint struct {
	Label   string `json:"label"`
	Allowed int64  `json:"allowed"`
	Denied  int64  `json:"denied"`
}

type DashboardRank struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
	Count int64  `json:"count"`
}

type DashboardActivity struct {
	Time     time.Time `json:"time"`
	Title    string    `json:"title"`
	Resource string    `json:"resource"`
	Outcome  string    `json:"outcome"`
}

type DashboardResources struct {
	Capabilities int64 `json:"capabilities"`
	Credentials  int64 `json:"credentials"`
	Channels     int64 `json:"channels"`
	Threads      int64 `json:"threads"`
}

// DashboardRuntime 当前平台进程的 API 请求观测，窗口为最近 300 秒。
type DashboardRuntime struct {
	Current   int64     `json:"current"`
	Peak      int64     `json:"peak"`
	Requests  int64     `json:"requests"`
	AverageMS *float64  `json:"average_ms"`
	StartedAt time.Time `json:"started_at"`
}
