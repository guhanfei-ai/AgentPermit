package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"agentpermit/internal/auth"
	"agentpermit/internal/model"
	"agentpermit/internal/store"
)

const temporaryHeader = "AgentPermit-Temporary-Credential"
const serviceTokenPrefix = "ap_trust_service_"
const temporaryTokenPrefix = "ap_temporary_"

var beijing = time.FixedZone("Asia/Shanghai", 8*60*60)

type trustPage[T any] struct {
	Items              []T
	Page, Pages, Total int
	Prev, Next         string
}

type trustBanSection struct {
	Title string
	List  trustPage[*model.WorkBan]
	CSRF  string
}

func serverKinds() []string { return []string{"MCP", "Server", "Nginx", "其他"} }

func paginateTrust[T any](r *http.Request, key string, items []T) trustPage[T] {
	const size = 10
	page, _ := strconv.Atoi(r.URL.Query().Get(key))
	if page < 1 {
		page = 1
	}
	pages := (len(items) + size - 1) / size
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	start := (page - 1) * size
	end := start + size
	if end > len(items) {
		end = len(items)
	}
	out := trustPage[T]{Items: items[start:end], Page: page, Pages: pages, Total: len(items)}
	link := func(n int) string {
		q := r.URL.Query()
		q.Set(key, strconv.Itoa(n))
		return r.URL.Path + "?" + q.Encode()
	}
	if page > 1 {
		out.Prev = link(page - 1)
	}
	if page < pages {
		out.Next = link(page + 1)
	}
	return out
}

func (s *Server) trustFailure(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	message := "服务暂时不可用，请稍后重试。"
	if err == store.ErrNotFound {
		status = http.StatusNotFound
		message = "记录不存在或无权访问。"
	}
	if err == store.ErrConflict {
		status = http.StatusConflict
		message = "登记信息重复，或已有未结束的节假日计划。"
	}
	if err == store.ErrInvalidTrust {
		status = http.StatusUnprocessableEntity
		message = "请检查对象归属、状态、有效期限和接入配置。"
	}
	if err == store.ErrInvalidFieldGroup {
		status = http.StatusUnprocessableEntity
		message = "变量编组不存在或不属于该Server。"
	}
	if err == store.ErrInvalidFieldValues {
		status = http.StatusUnprocessableEntity
		message = "申报值不符合编组定义。"
	}
	if status == http.StatusInternalServerError {
		s.logger.Error("授信管理失败", "err", err)
	}
	s.renderError(w, r, status, message)
}

func (s *Server) requireTrustAdmin(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return s.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.store.Holiday(r.Context())
		if err != nil {
			s.trustFailure(w, r, err)
			return
		}
		if p.State(s.store.Now()) == "active" {
			s.renderError(w, r, http.StatusLocked, "节假日封网生效中，请等待自动解除或使用解锁入口。")
			return
		}
		next(w, r)
	})
}

func (s *Server) trustRedirect(w http.ResponseWriter, r *http.Request, target, message string) {
	s.setFlash(w, "success", message)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

type trustGrantView struct {
	*model.TemporaryGrant
	Denial string
}

func (s *Server) pageTrust(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	p, err := s.store.Holiday(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	at := s.store.Now()
	data := map[string]any{"Holiday": p, "State": p.State(at), "Now": at.Unix(), "CanManage": u.IsAdmin(), "Defaults": trustDefaults(at)}
	if p.State(at) == "active" {
		s.renderPage(w, r, 200, "trust", "AI身份授信", "trust", data)
		return
	}
	owner := ""
	if !u.IsAdmin() {
		owner = u.ID
	}
	grants, err := s.store.ListTemporaryGrants(r.Context(), owner)
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	views := []trustGrantView{}
	history := r.URL.Query().Get("history") == "1"
	for _, g := range grants {
		code, e := s.store.GrantDenial(r.Context(), g)
		if e != nil {
			s.trustFailure(w, r, e)
			return
		}
		if history || code == "" {
			views = append(views, trustGrantView{g, code})
		}
	}
	data["History"] = history
	data["Grants"] = paginateTrust(r, "grants_page", views)
	servers, err := s.store.ListTrustedServers(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	data["Servers"] = servers
	// 管理员签发对话框需要全部Server的编组，按 ServerID 供表单联动筛选。
	if u.IsAdmin() {
		groups := []*model.FieldGroup{}
		for _, v := range servers {
			items, e := s.store.ListFieldGroups(r.Context(), v.ID)
			if e != nil {
				s.trustFailure(w, r, e)
				return
			}
			groups = append(groups, items...)
		}
		data["FieldGroups"] = groups
	}
	people, credentials, conditions := []*model.WorkBan{}, []*model.WorkBan{}, []*model.WorkBan{}
	if u.IsAdmin() {
		users, e := s.store.ListUsers(r.Context())
		if e != nil {
			s.trustFailure(w, r, e)
			return
		}
		data["Users"] = users
		choices := []*model.AgentCredential{}
		for _, person := range users {
			if !person.IsActive() {
				continue
			}
			items, e := s.store.ListAgentCredentialsByOwner(r.Context(), person.ID)
			if e != nil {
				s.trustFailure(w, r, e)
				return
			}
			for _, a := range items {
				if a.IsActive() {
					choices = append(choices, a)
				}
			}
		}
		data["Credentials"] = choices
		bans, e := s.store.ListWorkBans(r.Context())
		if e != nil {
			s.trustFailure(w, r, e)
			return
		}
		for _, b := range bans {
			if !history && (!b.ReleasedAt.IsZero() || !b.ExpiresAt.IsZero() && !at.Before(b.ExpiresAt)) {
				continue
			}
			switch b.Kind {
			case "person":
				people = append(people, b)
			case "credential":
				credentials = append(credentials, b)
			case "condition":
				conditions = append(conditions, b)
			}
		}
	}
	data["PersonBans"] = paginateTrust(r, "people_page", people)
	data["CredentialBans"] = paginateTrust(r, "credentials_page", credentials)
	data["ConditionBans"] = paginateTrust(r, "conditions_page", conditions)
	if u.IsAdmin() {
		csrf := s.csrfTokenFor(r, u)
		data["BanSections"] = []trustBanSection{{"封禁人员清单", paginateTrust(r, "people_page", people), csrf}, {"封禁AI凭证清单", paginateTrust(r, "credentials_page", credentials), csrf}, {"条件封禁清单", paginateTrust(r, "conditions_page", conditions), csrf}}
	}
	s.renderPage(w, r, 200, "trust", "AI身份授信", "trust", data)
}

func trustDefaults(at time.Time) map[string]string {
	return map[string]string{"HolidayEnd": at.Add(24 * time.Hour).In(beijing).Format("2006-01-02T15:04:05")}
}
func trustDate(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04"} {
		v, e := time.ParseInLocation(layout, raw, beijing)
		if e == nil {
			return v.UTC(), nil
		}
	}
	return time.Time{}, store.ErrInvalidTrust
}

func (s *Server) pageGrantCreate(w http.ResponseWriter, r *http.Request) {
	// 有效期由服务端固定为300秒，表单不再采集到期时间；
	// 兼容旧表单继续提交的 expires_at 一律忽略。
	values := strings.TrimSpace(r.PostFormValue("field_values"))
	if len(values) > 8192 {
		s.trustFailure(w, r, store.ErrInvalidFieldValues)
		return
	}
	token, hash, hint := auth.NewToken(temporaryTokenPrefix)
	g := &model.TemporaryGrant{ID: store.NewID(), UserID: r.PostFormValue("user_id"), CredentialID: r.PostFormValue("credential_id"), ServerID: r.PostFormValue("server_id"), IssuedBy: userFrom(r.Context()).ID, TokenHash: hash, TokenHint: hint, GroupID: r.PostFormValue("field_group_id"), GroupValues: values}
	if err := s.store.IssueTemporaryGrant(r.Context(), g); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "temporary_grant_issued", ActorUserID: g.IssuedBy, SubjectUserID: g.UserID, CredentialID: g.CredentialID, Detail: "grant_id=" + g.ID + " server_id=" + g.ServerID + " via=web"})
	s.showTrustSecret(w, r, "临时授信凭证", token, "/trust/grants/"+g.ID)
}

func (s *Server) pageGrantDetail(w http.ResponseWriter, r *http.Request) {
	g, err := s.store.GetTemporaryGrant(r.Context(), r.PathValue("id"))
	u := userFrom(r.Context())
	if err != nil || !u.IsAdmin() && g.UserID != u.ID {
		s.trustFailure(w, r, store.ErrNotFound)
		return
	}
	p, err := s.store.Holiday(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if p.State(s.store.Now()) == "active" {
		http.Redirect(w, r, "/trust", http.StatusSeeOther)
		return
	}
	code, err := s.store.GrantDenial(r.Context(), g)
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.renderPage(w, r, 200, "trust_detail", "临时授信详情", "trust", map[string]any{"Grant": g, "Denial": code, "FieldValues": store.FormatFieldGroupValues(g.GroupValues)})
}
func (s *Server) pageGrantRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	g, err := s.store.GetTemporaryGrant(r.Context(), id)
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if err = s.store.RevokeTemporaryGrant(r.Context(), id, userFrom(r.Context()).ID, ""); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "temporary_grant_revoked", ActorUserID: userFrom(r.Context()).ID, SubjectUserID: g.UserID, CredentialID: g.CredentialID, Detail: "grant_id=" + id + " server_id=" + g.ServerID})
	s.trustRedirect(w, r, "/trust", "临时授信已撤销。")
}

func (s *Server) pageBanSave(w http.ResponseWriter, r *http.Request) {
	starts, err := trustDate(r.PostFormValue("starts_at"))
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if starts.IsZero() {
		starts = s.store.Now()
	}
	expires, err := trustDate(r.PostFormValue("expires_at"))
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	b := &model.WorkBan{ID: r.PathValue("id"), Kind: r.PostFormValue("kind"), Name: strings.TrimSpace(r.PostFormValue("name")), UserID: r.PostFormValue("user_id"), CredentialID: r.PostFormValue("credential_id"), ServerID: r.PostFormValue("server_id"), Environment: strings.TrimSpace(r.PostFormValue("environment")), Reason: strings.TrimSpace(r.PostFormValue("reason")), CreatedBy: userFrom(r.Context()).ID, StartsAt: starts, ExpiresAt: expires}
	if len(b.Reason) > 500 || len(b.Name) > 128 || len(b.Environment) > 64 || b.Kind == "condition" && b.UserID == "" && b.CredentialID == "" && b.ServerID == "" && b.Environment == "" && r.PostFormValue("all_scope") != "yes" {
		s.trustFailure(w, r, store.ErrInvalidTrust)
		return
	}
	edit := b.ID != ""
	if !edit {
		b.ID = store.NewID()
	} else {
		old, e := s.store.GetWorkBan(r.Context(), b.ID)
		if e != nil || old.Kind != "condition" || b.Kind != "condition" {
			s.trustFailure(w, r, store.ErrNotFound)
			return
		}
	}
	if err := s.store.SaveWorkBan(r.Context(), b, edit); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "work_ban_saved", ActorUserID: b.CreatedBy, SubjectUserID: b.UserID, CredentialID: b.CredentialID, Detail: "ban_id=" + b.ID + " kind=" + b.Kind})
	s.trustRedirect(w, r, "/trust", "封禁规则已保存。")
}
func (s *Server) pageBanDetail(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.GetWorkBan(r.Context(), r.PathValue("id"))
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	p, err := s.store.Holiday(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if p.State(s.store.Now()) == "active" {
		http.Redirect(w, r, "/trust", 303)
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	servers, err := s.store.ListTrustedServers(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.renderPage(w, r, 200, "trust_detail", "封禁详情", "trust", map[string]any{"Ban": b, "Users": users, "Servers": servers})
}
func (s *Server) pageBanRelease(w http.ResponseWriter, r *http.Request) {
	b, err := s.store.GetWorkBan(r.Context(), r.PathValue("id"))
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if err := s.store.ReleaseWorkBan(r.Context(), b.ID, userFrom(r.Context()).ID); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "work_ban_released", ActorUserID: userFrom(r.Context()).ID, SubjectUserID: b.UserID, CredentialID: b.CredentialID, Detail: "ban_id=" + b.ID})
	s.trustRedirect(w, r, "/trust", "该条封禁已解除，其他规则继续生效。")
}

func (s *Server) pageHolidayCreate(w http.ResponseWriter, r *http.Request) {
	hash, err := s.store.GetHolidayUnlockPasswordHash(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if hash == "" {
		s.renderError(w, r, http.StatusConflict, "请先在系统设置中设置解锁密码，再创建全局暂停计划。")
		return
	}
	trigger, err := trustDate(r.PostFormValue("trigger_at"))
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if trigger.IsZero() {
		trigger = s.store.Now()
	}
	ends, err := trustDate(r.PostFormValue("ends_at"))
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	if reason == "" || len(reason) > 500 {
		s.trustFailure(w, r, store.ErrInvalidTrust)
		return
	}
	p := &model.HolidayPlan{ID: store.NewID(), CreatedBy: userFrom(r.Context()).ID, Reason: reason, TriggerAt: trigger, EndsAt: ends}
	if err := s.store.CreateHoliday(r.Context(), p); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "holiday_scheduled", ActorUserID: p.CreatedBy, Detail: fmt.Sprintf("plan_id=%s lock_at=%d ends_at=%d", p.ID, p.LockAt.Unix(), p.EndsAt.Unix())})
	s.trustRedirect(w, r, "/trust", "节假日计划已保存，触发后10秒统一封网。")
}
func (s *Server) pageHolidayUnlock(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	if !s.limiter.Allow("holiday-unlock:" + u.ID + ":" + clientIP(r)) {
		s.renderError(w, r, 429, "尝试过于频繁，请稍后重试。")
		return
	}
	currentHash, err := s.store.GetHolidayUnlockPasswordHash(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if !auth.CheckPassword(currentHash, r.PostFormValue("password")) {
		s.audit(r, &model.AuditLog{Event: "holiday_unlock_failed", ActorUserID: u.ID, Outcome: "failure", Reason: "invalid_password"})
		s.renderError(w, r, 403, "解锁密码错误，封网状态保持不变。")
		return
	}
	p, err := s.store.Holiday(r.Context())
	if err != nil {
		s.trustFailure(w, r, err)
		return
	}
	if p == nil {
		s.trustFailure(w, r, store.ErrNotFound)
		return
	}
	if err := s.store.UnlockHoliday(r.Context(), p.ID, u.ID); err != nil {
		s.trustFailure(w, r, err)
		return
	}
	s.audit(r, &model.AuditLog{Event: "holiday_unlocked", ActorUserID: u.ID, Detail: "plan_id=" + p.ID})
	s.trustRedirect(w, r, "/trust", "本次节假日封网已解锁，其他封禁继续生效。")
}

func (s *Server) trustState(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.Holiday(r.Context())
	if err != nil {
		s.jsonError(w, r, 503, "unavailable", "无法获取当前封网状态")
		return
	}
	data := map[string]any{"now": s.store.Now().Unix(), "state": p.State(s.store.Now())}
	if p != nil {
		data["trigger_at"] = p.TriggerAt.Unix()
		data["lock_at"] = p.LockAt.Unix()
		data["ends_at"] = p.EndsAt.Unix()
	}
	writeJSON(w, r, 200, data)
}
