package policy

import (
	"testing"

	"agentpermit/internal/model"
)

// 构造测试夹具：所有者王五、调用者张三、默认 team 模式的有效能力。
func fixture(mut ...func(in *Input)) Input {
	owner := &model.User{ID: "u-owner", Username: "wangwu", Status: model.StatusActive}
	caller := &model.User{ID: "u-caller", Username: "zhangsan", Status: model.StatusActive}
	agent := &model.Agent{ID: "a-1", OwnerUserID: caller.ID, Status: model.StatusActive}
	capability := &model.Capability{ID: "c-1", OwnerUserID: owner.ID, Status: model.StatusActive, AccessMode: model.AccessModeTeam}
	in := Input{Agent: agent, AgentOwner: caller, Capability: capability, CapOwner: owner}
	for _, m := range mut {
		m(&in)
	}
	return in
}

func TestTeamModeAllowsValidTeamUser(t *testing.T) {
	// 1. team 模式允许有效团队用户
	d := Evaluate(fixture())
	if !d.Allowed || d.Reason != ReasonAllowed || d.Basis != BasisTeam {
		t.Fatalf("team 模式应允许，得到 %+v", d)
	}
}

func TestDenylistRejects(t *testing.T) {
	// 2. 黑名单拒绝
	d := Evaluate(fixture(func(in *Input) { in.Denied = true }))
	if d.Allowed || d.Reason != ReasonUserBlacklisted {
		t.Fatalf("黑名单应拒绝，得到 %+v", d)
	}
}

func TestDenylistTakesPrecedenceOverAllowlist(t *testing.T) {
	// 3. 同时位于黑白名单，黑名单优先
	d := Evaluate(fixture(func(in *Input) {
		in.Denied = true
		in.Allowlisted = true
		in.Capability.AccessMode = model.AccessModeAllowlist
	}))
	if d.Allowed || d.Reason != ReasonUserBlacklisted {
		t.Fatalf("黑名单应优先，得到 %+v", d)
	}
}

func TestAllowlistModeAllowsListedUser(t *testing.T) {
	// 4. allowlist 模式允许白名单用户
	d := Evaluate(fixture(func(in *Input) {
		in.Capability.AccessMode = model.AccessModeAllowlist
		in.Allowlisted = true
	}))
	if !d.Allowed || d.Basis != BasisAllowlist {
		t.Fatalf("白名单模式应允许白名单用户，得到 %+v", d)
	}
}

func TestAllowlistModeRejectsUnlistedUser(t *testing.T) {
	// 5. allowlist 模式拒绝非白名单用户
	d := Evaluate(fixture(func(in *Input) { in.Capability.AccessMode = model.AccessModeAllowlist }))
	if d.Allowed || d.Reason != ReasonUserNotAllowlisted {
		t.Fatalf("白名单模式应拒绝未列用户，得到 %+v", d)
	}
}

func TestOwnerAlwaysAllowed(t *testing.T) {
	// 6. 能力所有者允许（即使在 allowlist 模式且不在白名单中）
	d := Evaluate(fixture(func(in *Input) {
		in.Agent.OwnerUserID = "u-owner" // 调用 Agent 属于所有者
		in.AgentOwner = &model.User{ID: "u-owner", Status: model.StatusActive}
		in.Capability.AccessMode = model.AccessModeAllowlist
		in.Allowlisted = false
	}))
	if !d.Allowed || d.Basis != BasisOwner {
		t.Fatalf("所有者应允许，得到 %+v", d)
	}
}

func TestRevokedAgentRejected(t *testing.T) {
	// 7. 已撤销 Agent 拒绝
	d := Evaluate(fixture(func(in *Input) { in.Agent.Status = model.StatusRevoked }))
	if d.Allowed || d.Reason != ReasonAgentRevoked {
		t.Fatalf("已撤销 Agent 应拒绝，得到 %+v", d)
	}
}

func TestDisabledUserRejected(t *testing.T) {
	// 8. 已禁用用户拒绝（Agent 所属用户被禁用）
	d := Evaluate(fixture(func(in *Input) { in.AgentOwner.Status = model.StatusDisabled }))
	if d.Allowed || d.Reason != ReasonUserDisabled {
		t.Fatalf("禁用用户应拒绝，得到 %+v", d)
	}
}

func TestDisabledCapabilityRejected(t *testing.T) {
	// 9. 已停用能力拒绝（对所有人生效，包括所有者）
	in := fixture(func(in *Input) { in.Capability.Status = model.StatusDisabled })
	d := Evaluate(in)
	if d.Allowed || d.Reason != ReasonCapabilityDisabled {
		t.Fatalf("停用能力应拒绝，得到 %+v", d)
	}
	// 所有者自己的 Agent 也会被拒绝
	in.Agent.OwnerUserID = "u-owner"
	in.AgentOwner = &model.User{ID: "u-owner", Status: model.StatusActive}
	d = Evaluate(in)
	if d.Allowed || d.Reason != ReasonCapabilityDisabled {
		t.Fatalf("停用能力对所有者也应拒绝，得到 %+v", d)
	}
}

func TestDisabledOwnerRejected(t *testing.T) {
	// 10. 能力所有者禁用后拒绝
	d := Evaluate(fixture(func(in *Input) { in.CapOwner.Status = model.StatusDisabled }))
	if d.Allowed || d.Reason != ReasonOwnerDisabled {
		t.Fatalf("所有者禁用应拒绝，得到 %+v", d)
	}
}

func TestAdminDoesNotBypass(t *testing.T) {
	// 11. 管理员不能绕过能力访问策略
	// role=admin 但非所有者、未在白名单中 → allowlist 模式下应拒绝
	in := fixture(func(in *Input) {
		in.Capability.AccessMode = model.AccessModeAllowlist
		in.AgentOwner.Role = model.UserRoleAdmin
	})
	d := Evaluate(in)
	if d.Allowed {
		t.Fatalf("管理员不应绕过 allowlist，得到 %+v", d)
	}
	// 黑名单同样对管理员生效
	in2 := fixture(func(in *Input) {
		in.Denied = true
		in.AgentOwner.Role = model.UserRoleAdmin
	})
	d2 := Evaluate(in2)
	if d2.Allowed || d2.Reason != ReasonUserBlacklisted {
		t.Fatalf("管理员被拉黑应拒绝，得到 %+v", d2)
	}
}

func TestInvalidAgentToken(t *testing.T) {
	// 补充：Token 无效（查无此 Agent）
	d := Evaluate(Input{Agent: nil, Capability: &model.Capability{Status: model.StatusActive}, CapOwner: &model.User{Status: model.StatusActive}})
	if d.Allowed || d.Reason != ReasonInvalidAgentToken {
		t.Fatalf("无效 Token 应拒绝，得到 %+v", d)
	}
}
