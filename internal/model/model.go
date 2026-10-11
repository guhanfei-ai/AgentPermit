// Package model 定义平台的数据结构。字段名与数据库列一一对应。
package model

import "time"

// 时间统一以 UTC RFC3339 文本存储。
const TimeLayout = time.RFC3339

const (
	UserRoleUser  = "user"
	UserRoleAdmin = "admin"

	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusRevoked  = "revoked"

	AccessModeTeam      = "team"
	AccessModeAllowlist = "allowlist"

	ProjectStatusActive   = "active"
	ProjectStatusArchived = "archived"

	ThreadStatusOpen   = "open"
	ThreadStatusClosed = "closed"

	// MaxFloorsPerThread 单个留言板（含首帖）的楼层上限，写满后仅可读。
	MaxFloorsPerThread = 5000
)

// User 真人账号，授权主体。
type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string
	Role         string // user / admin
	Status       string // active / disabled
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IsAdmin 报告是否平台管理员。管理员可管理用户与项目、查看全局审计，能力访问仍需通过策略校验。
func (u *User) IsAdmin() bool { return u != nil && u.Role == UserRoleAdmin }

// IsActive 报告账号是否启用。
func (u *User) IsActive() bool { return u != nil && u.Status == StatusActive }

// Session 网页登录会话。数据库只保存 Token 的 SHA-256 摘要。
type Session struct {
	TokenHash string
	UserID    string
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Agent 归属于某个真人用户的 Agent 身份。
type Agent struct {
	ID          string
	OwnerUserID string
	Name        string
	Description string
	Status      string // active / revoked
	TokenHash   string
	TokenHint   string // 形如 ap_agent_…ABCD（更名前为 aad_agent_…），仅用于列表识别，非原文
	CreatedAt   time.Time
	RevokedAt   *time.Time
}

// IsActive 报告 Agent 是否有效。
func (a *Agent) IsActive() bool { return a != nil && a.Status == StatusActive }

// Capability 用户维护的团队能力，包含内容与 HTTP 工具绑定。
// 可编辑字段构成内容「草稿」；对外只暴露 latest_version 指向的已发布快照。
type Capability struct {
	ID            string
	OwnerUserID   string
	Name          string
	Slug          string
	Description   string
	EndpointURL   string
	HTTPMethod    string
	APIPath       string
	SpecMarkdown  string
	AccessMode    string // team / allowlist
	Status        string // active / disabled
	LatestVersion int    // latest 标记指向的已发布版本，0 = 尚未发布
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// CapabilityVersion 能力内容的不可变发布快照。
// 内容（描述 / SPEC / RUNBOOK 等 Markdown）是主体，接口字段保存 HTTP 工具绑定。
type CapabilityVersion struct {
	ID           string
	CapabilityID string
	Version      int
	Name         string
	Description  string
	EndpointURL  string
	HTTPMethod   string
	APIPath      string
	SpecMarkdown string
	PublishedBy  string
	PublishedAt  time.Time
	// 展示用联查字段
	PublishedByUsername string
}

// Project 协作空间项目。留言板隶属于项目，不隶属于能力或个人。
type Project struct {
	ID          string
	Slug        string
	Name        string
	Description string
	Status      string // active / archived
	CreatedBy   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// 展示用联查字段
	CreatedByUsername string
	CreatedByDisplay  string
	ThreadCount       int
}

// IsActive 报告项目是否处于活跃状态（归档后只读）。
func (p *Project) IsActive() bool { return p != nil && p.Status == ProjectStatusActive }

// Thread 留言板（线程）。仅真人可创建；楼层上限 MaxFloorsPerThread。
type Thread struct {
	ID         string
	ProjectID  string
	Title      string
	Status     string // open / closed
	CreatedBy  string
	FloorCount int
	ClosedAt   *time.Time
	ClosedBy   string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	// 展示用联查字段
	CreatedByUsername string
	CreatedByDisplay  string
	ProjectSlug       string
	ProjectName       string
	ProjectStatus     string
	LastFloorAt       time.Time
}

// IsOpen 报告留言板是否开放追加。
func (t *Thread) IsOpen() bool { return t != nil && t.Status == ThreadStatusOpen }

// Floor 楼层。仅追加、不编辑不删除；AgentID 为空表示真人发言。
type Floor struct {
	ID           string
	ThreadID     string
	FloorNo      int
	AuthorUserID string
	AgentID      string
	Body         string
	CreatedAt    time.Time
	// 展示用联查字段
	AuthorUsername    string
	AuthorDisplayName string
	AgentName         string
}

// IsAgent 报告楼层是否由 Agent 发表。
func (f *Floor) IsAgent() bool { return f != nil && f.AgentID != "" }

// ProjectBan 项目禁言条目。AgentID 为空表示 user 级（覆盖该真人全部 Agent 与本人网页发言）。
type ProjectBan struct {
	ProjectID string
	UserID    string
	AgentID   string // '' = user 级禁言
	Reason    string
	BannedBy  string
	CreatedAt time.Time
	// 展示用联查字段
	Username         string
	DisplayName      string
	AgentName        string
	BannedByUsername string
}

// ProjectDoc 项目唯一的 AGENTS.md 文档：草稿 + latest 标记。
type ProjectDoc struct {
	ProjectID         string
	DraftBody         string
	DraftUpdatedBy    string
	DraftUpdatedAt    *time.Time
	LatestVersion     int // 0 = 尚未发布
	LatestPublishedAt *time.Time
}

// ProjectDocVersion AGENTS.md 的不可变发布版本。
type ProjectDocVersion struct {
	ProjectID   string
	Version     int
	Body        string
	PublishedBy string
	PublishedAt time.Time
	// 展示用联查字段
	PublishedByUsername string
}

// IsActive 报告能力是否启用。
func (c *Capability) IsActive() bool { return c != nil && c.Status == StatusActive }

// ServiceCredential 能力的服务端验证凭证，数据库只保存摘要。
type ServiceCredential struct {
	CapabilityID string
	TokenHash    string
	TokenHint    string
	CreatedAt    time.Time
	RotatedAt    *time.Time
}

// ListEntry 黑名单或白名单条目（关联用户名用于展示）。
type ListEntry struct {
	CapabilityID string
	UserID       string
	Username     string
	DisplayName  string
	CreatedAt    time.Time
}

// AuditLog 审计记录。绝不包含任何凭证原文。
type AuditLog struct {
	ID            int64
	CreatedAt     time.Time
	Event         string
	ActorUserID   string // 可空
	AgentID       string // 可空
	CapabilityID  string // 可空
	ProjectID     string // 可空
	ThreadID      string // 可空
	SubjectUserID string // 授权判断针对的用户，可空
	Outcome       string // success / failure
	Reason        string
	RequestID     string
	Detail        string
	// 展示用联查字段
	ActorUsername  string
	CapabilityName string
	ProjectName    string
}
