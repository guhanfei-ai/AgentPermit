// Package policy 是唯一的访问策略评估器。
// Agent 能力列表、能力详情、独立服务授权校验全部经由 Evaluate/EvaluateForUser，
// 任何 Handler 不得自行拼装规则。
//
// 授权主体是真人账号（user），不是 Agent：黑名单、白名单均以 user_id 为准，
// 对某账号生效即覆盖其名下所有调用凭证访问该能力的请求。
package policy

import "agentpermit/internal/model"

// 拒绝原因采用稳定机器可读枚举。
const (
	ReasonAllowed            = "allowed"
	ReasonInvalidAgentToken  = "invalid_agent_token"
	ReasonAgentRevoked       = "agent_revoked"
	ReasonUserDisabled       = "user_disabled"
	ReasonOwnerDisabled      = "owner_disabled"
	ReasonCapabilityDisabled = "capability_disabled"
	ReasonUserBlacklisted    = "user_blacklisted"
	ReasonUserNotAllowlisted = "user_not_allowlisted"
	ReasonNoHTTPBinding      = "no_http_binding"
)

// Basis 是允许时的判定依据（审计用细分，对外 reason 统一为 allowed）。
const (
	BasisOwner     = "owner"
	BasisTeam      = "team"
	BasisAllowlist = "allowlist"
)

// Input 是策略评估所需的全部输入快照（由调用方一次性从数据库读取）。
type Input struct {
	// 调用凭证记录；nil 表示 Token 无效。
	Credential *model.AgentCredential
	// 凭证所属真人账号；Credential 非 nil 时必须提供。
	CredentialOwner *model.User
	// 目标能力；nil 由调用方先行处理为 404，不会传入。
	Capability *model.Capability
	// 能力所有者。
	CapOwner *model.User
	// 调用方用户是否在该能力黑名单中。
	Denied bool
	// 调用方用户是否在该能力白名单中。
	Allowlisted bool
}

// Decision 是评估结果。
type Decision struct {
	Allowed bool
	// 拒绝原因或 "allowed"。
	Reason string
	// 允许时的细分依据：owner / team / allowlist。
	Basis string
}

// Evaluate 按 Agent 调用路径评估，顺序严格固定：
//  1. 调用凭证有效且 active；
//  2. 凭证所属账号 active；
//  3. 能力 active；
//  4. 能力所有者 active；
//  5. 调用者是能力所有者 → 允许；
//  6. 黑名单 → 拒绝（黑名单优先于白名单）；
//  7. team 模式：同默认团队有效用户允许；
//  8. allowlist 模式：仅白名单用户允许；
//  9. 其他拒绝。
//
// 管理员角色不参与能力访问判定。
func Evaluate(in Input) Decision {
	// 1. 调用凭证
	if in.Credential == nil || in.CredentialOwner == nil {
		return deny(ReasonInvalidAgentToken)
	}
	if in.Credential.Status != model.StatusActive {
		return deny(ReasonAgentRevoked)
	}
	// 2. 凭证所属账号
	if in.CredentialOwner.Status != model.StatusActive {
		return deny(ReasonUserDisabled)
	}
	return evaluateForUser(in.Credential.OwnerUserID, in)
}

// EvaluateHTTPService 在账号访问策略通过后检查当前发布版本的工具作用域。
// 纯内容版本可读取，但不授权独立 HTTP 服务调用；已有访问拒绝优先保留。
func EvaluateHTTPService(access Decision, published *model.CapabilityVersion) Decision {
	if !access.Allowed {
		return access
	}
	if !published.HasHTTPBinding() {
		return deny(ReasonNoHTTPBinding)
	}
	return access
}

// EvaluateForUser 按“已登录真人用户”路径评估（Web 能力目录页使用）。
// 登录用户必然 active（会话中间件保证），但仍做防御性检查。
func EvaluateForUser(u *model.User, in Input) Decision {
	if u == nil || u.Status != model.StatusActive {
		return deny(ReasonUserDisabled)
	}
	return evaluateForUser(u.ID, in)
}

func evaluateForUser(callerUserID string, in Input) Decision {
	capability := in.Capability
	if capability == nil || in.CapOwner == nil {
		// 调用方约定不会出现；防御性拒绝。
		return deny(ReasonCapabilityDisabled)
	}
	// 3. 能力状态
	if capability.Status != model.StatusActive {
		return deny(ReasonCapabilityDisabled)
	}
	// 4. 能力所有者状态
	if in.CapOwner.Status != model.StatusActive {
		return deny(ReasonOwnerDisabled)
	}
	// 5. 所有者本人始终允许（黑名单不可作用于所有者，由管理端强制）
	if callerUserID == capability.OwnerUserID {
		return allow(BasisOwner)
	}
	// 6. 黑名单优先于白名单
	if in.Denied {
		return deny(ReasonUserBlacklisted)
	}
	// 7/8. 访问模式
	switch capability.AccessMode {
	case model.AccessModeTeam:
		// 第一版所有有效注册用户同属默认团队。
		return allow(BasisTeam)
	case model.AccessModeAllowlist:
		if in.Allowlisted {
			return allow(BasisAllowlist)
		}
		return deny(ReasonUserNotAllowlisted)
	default:
		return deny(ReasonUserNotAllowlisted)
	}
}

func allow(basis string) Decision {
	return Decision{Allowed: true, Reason: ReasonAllowed, Basis: basis}
}

func deny(reason string) Decision {
	return Decision{Allowed: false, Reason: reason}
}
