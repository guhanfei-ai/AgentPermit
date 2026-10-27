package model

import "time"

// TemporaryGrantTTL 是临时凭证唯一合法有效期：固定300秒。
// 这不是默认值或可配置上限——任何入口都不允许签出更长或更短的凭证，
// 不够用时由持有永久凭证的 Agent 重新申请一份新临时凭证。
const TemporaryGrantTTL = 300 * time.Second

// TrustedServer 是独立于频道内容的受管服务接入身份（服务登记）。
// 一个 Gateway 一张服务登记，其下可挂多个能力契约变量编组。
type TrustedServer struct {
	ID, Name, Kind, Description, Environment, Origin, OwnerUserID string
	Status                                                        string
	TokenHash                                                     string `json:"-"`
	TokenHint                                                     string
	CreatedAt, UpdatedAt                                          time.Time
	OwnerName                                                     string
	LastCheckedAt                                                 time.Time
}

// FieldGroup 是服务登记下的能力契约变量编组：维护者预设字段类型与约束，
// 使用者 Agent 在签发临时凭证时临时填值。v1 一份临时凭证至多绑定一个编组。
type FieldGroup struct {
	ID, ServerID, Name, Description string
	Definition                      string // 规范 JSON，见 FieldGroupDefinition
	CreatedBy                       string
	CreatedAt, UpdatedAt            time.Time
	ServerName, CreatorName         string
}

// FieldGroupField 是编组中的单个变量定义。
type FieldGroupField struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     string   `json:"type"` // enum 或 string
	Options  []string `json:"options,omitempty"`
	Required bool     `json:"required,omitempty"`
	MaxLen   int      `json:"max_len,omitempty"`
}

// FieldGroupDefinition 是编组定义的持久化结构；签发时整体快照到临时授信。
type FieldGroupDefinition struct {
	Fields []FieldGroupField `json:"fields"`
}

// TemporaryGrant 绑定人员、原始凭证、指定服务与到期时间。
// GroupID 为空表示未申报编组；非空时 GroupSnapshot 保存签发当时的定义，
// GroupValues 保存本次申报值，后续定义变更不影响已签发凭证。
type TemporaryGrant struct {
	ID, UserID, CredentialID, ServerID               string
	ParentTokenHash                                  string `json:"-"`
	TokenHash                                        string `json:"-"`
	TargetOrigin, TokenHint, IssuedBy                string
	IssuedAt, ExpiresAt                              time.Time
	RevokedAt, LastCheckedAt                         time.Time
	GroupID, GroupValues, GroupSnapshot, GroupName   string
	UserName, CredentialName, ServerName, IssuerName string
}

// EffectiveExpiresAt 返回核验实际承认的到期时间。
// 固定300秒规则同时收口存量长授信：签发300秒后即失效，
// 即使历史记录里存有更长的到期时间；更短的按原到期时间。
func (g *TemporaryGrant) EffectiveExpiresAt() time.Time {
	capped := g.IssuedAt.Add(TemporaryGrantTTL)
	if g.ExpiresAt.Before(capped) {
		return g.ExpiresAt
	}
	return capped
}

// WorkBan 的空范围表示该维度不限；不同维度同时匹配。
type WorkBan struct {
	ID, Kind, Name, UserID, CredentialID, ServerID, Environment, Reason, CreatedBy string
	StartsAt, ExpiresAt, ReleasedAt                                                time.Time
	UserName, CredentialName, ServerName, CreatorName                              string
}

type HolidayPlan struct {
	ObservedState                         string `json:"-"`
	ID, CreatedBy, Reason                 string
	TriggerAt, LockAt, EndsAt, UnlockedAt time.Time
}

func (p *HolidayPlan) State(at time.Time) string {
	if p == nil {
		return "none"
	}
	if !p.UnlockedAt.IsZero() {
		return "unlocked"
	}
	if !at.Before(p.EndsAt) {
		return "ended"
	}
	if at.Before(p.TriggerAt) {
		return "scheduled"
	}
	if at.Before(p.LockAt) {
		return "countdown"
	}
	return "active"
}
