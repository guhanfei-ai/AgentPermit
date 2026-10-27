package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"agentpermit/internal/model"
)

var (
	ErrInvalidTrust = errors.New("invalid trust configuration")
	// ErrInvalidFieldGroup 表示申报的编组不存在或不属于目标Server。
	ErrInvalidFieldGroup = errors.New("invalid field group")
	// ErrInvalidFieldValues 表示申报值不符合编组定义。
	ErrInvalidFieldValues = errors.New("invalid field values")
)

type trustQuery interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func trustTime(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}
func trustUnix(v time.Time) int64 {
	if v.IsZero() {
		return 0
	}
	return v.Unix()
}

const serverSelect = `SELECT s.id,s.name,s.kind,s.description,s.environment,s.origin,s.owner_user_id,s.status,s.token_hash,s.token_hint,s.created_at,s.updated_at,u.display_name,COALESCE((SELECT MAX(g.last_checked_at) FROM temporary_grants g WHERE g.server_id=s.id),0) FROM trusted_servers s JOIN users u ON u.id=s.owner_user_id`

func scanServer(row interface{ Scan(...any) error }) (*model.TrustedServer, error) {
	var s model.TrustedServer
	var created, updated, checked int64
	err := row.Scan(&s.ID, &s.Name, &s.Kind, &s.Description, &s.Environment, &s.Origin, &s.OwnerUserID, &s.Status, &s.TokenHash, &s.TokenHint, &created, &updated, &s.OwnerName, &checked)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt, s.UpdatedAt = trustTime(created), trustTime(updated)
	s.LastCheckedAt = trustTime(checked)
	return &s, nil
}

// ListTrustedServers 返回全部登记Server。v1统一使用资格：已接入并启用的入口
// 按统一基线提供给有效注册用户，不再按 public/admin 可见性筛选使用资格；
// 修改登记、轮换密钥等管理操作仍由管理身份保护。
func (s *Store) ListTrustedServers(ctx context.Context) ([]*model.TrustedServer, error) {
	rows, err := s.db.QueryContext(ctx, serverSelect+` ORDER BY s.created_at DESC,s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.TrustedServer{}
	for rows.Next() {
		v, e := scanServer(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetTrustedServer(ctx context.Context, id string) (*model.TrustedServer, error) {
	return scanServer(s.db.QueryRowContext(ctx, serverSelect+` WHERE s.id=?`, id))
}

func (s *Store) SaveTrustedServer(ctx context.Context, v *model.TrustedServer, create bool) error {
	at := s.Now().Unix()
	var err error
	if create {
		// visibility 列保留给旧库；v1统一使用资格下新登记一律 public，不再区分可见范围。
		_, err = s.db.ExecContext(ctx, `INSERT INTO trusted_servers(id,name,kind,description,environment,origin,owner_user_id,status,visibility,token_hash,token_hint,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, v.ID, v.Name, v.Kind, v.Description, v.Environment, v.Origin, v.OwnerUserID, v.Status, "public", v.TokenHash, v.TokenHint, at, at)
	} else {
		err = s.withTx(ctx, func(tx *sql.Tx) error {
			var oldOrigin, oldEnvironment string
			if e := tx.QueryRowContext(ctx, `SELECT origin,environment FROM trusted_servers WHERE id=?`, v.ID).Scan(&oldOrigin, &oldEnvironment); e != nil {
				if e == sql.ErrNoRows {
					return ErrNotFound
				}
				return e
			}
			if _, e := tx.ExecContext(ctx, `UPDATE trusted_servers SET name=?,kind=?,description=?,environment=?,origin=?,owner_user_id=?,status=?,updated_at=? WHERE id=?`, v.Name, v.Kind, v.Description, v.Environment, v.Origin, v.OwnerUserID, v.Status, at, v.ID); e != nil {
				return e
			}
			// 目标地址或环境变化后，旧授信不可因配置改回而恢复。
			if oldOrigin != v.Origin || oldEnvironment != v.Environment {
				_, e := tx.ExecContext(ctx, `UPDATE temporary_grants SET revoked_at=? WHERE server_id=? AND revoked_at=0`, at, v.ID)
				return e
			}
			return nil
		})
	}
	if isUniqueViolation(err) {
		return ErrConflict
	}
	return err
}

func (s *Store) RotateServerKey(ctx context.Context, id, hash, hint string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE trusted_servers SET token_hash=?,token_hint=?,updated_at=? WHERE id=?`, hash, hint, s.Now().Unix(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- 能力契约变量编组 ----

var fieldGroupKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

const (
	fieldGroupMaxFields     = 20
	fieldGroupMaxOptions    = 16
	fieldGroupValueMaxRunes = 512
	fieldGroupValuesMaxByte = 8192
)

// parseFieldGroupDefinition 严格解析并校验编组定义，返回规范化后的 JSON。
// 定义是维护者预设的类型与约束，不承载业务审批语义。
func parseFieldGroupDefinition(raw string) (string, *model.FieldGroupDefinition, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > fieldGroupValuesMaxByte {
		return "", nil, ErrInvalidTrust
	}
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var def model.FieldGroupDefinition
	if err := decoder.Decode(&def); err != nil {
		return "", nil, ErrInvalidTrust
	}
	// 只接受一个完整 JSON 值：解码结束必须是 EOF，尾随第二个值或损坏字符都拒绝。
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", nil, ErrInvalidTrust
	}
	if len(def.Fields) == 0 || len(def.Fields) > fieldGroupMaxFields {
		return "", nil, ErrInvalidTrust
	}
	seen := map[string]bool{}
	for i := range def.Fields {
		f := &def.Fields[i]
		f.Key = strings.TrimSpace(f.Key)
		f.Label = strings.TrimSpace(f.Label)
		if !fieldGroupKeyPattern.MatchString(f.Key) || seen[f.Key] {
			return "", nil, ErrInvalidTrust
		}
		seen[f.Key] = true
		if f.Label == "" {
			f.Label = f.Key
		}
		if utf8.RuneCountInString(f.Label) > 64 {
			return "", nil, ErrInvalidTrust
		}
		switch f.Type {
		case "enum":
			if len(f.Options) < 1 || len(f.Options) > fieldGroupMaxOptions {
				return "", nil, ErrInvalidTrust
			}
			optionSeen := map[string]bool{}
			for j, option := range f.Options {
				f.Options[j] = strings.TrimSpace(option)
				if f.Options[j] == "" || optionSeen[f.Options[j]] || utf8.RuneCountInString(f.Options[j]) > fieldGroupValueMaxRunes {
					return "", nil, ErrInvalidTrust
				}
				optionSeen[f.Options[j]] = true
			}
		case "string":
			f.Options = nil
			if f.MaxLen <= 0 {
				f.MaxLen = 128
			}
			if f.MaxLen > fieldGroupValueMaxRunes {
				return "", nil, ErrInvalidTrust
			}
		default:
			return "", nil, ErrInvalidTrust
		}
	}
	canonical, err := json.Marshal(def)
	if err != nil {
		return "", nil, err
	}
	return string(canonical), &def, nil
}

// validateFieldValues 校验申报值并返回按键排序的规范化 JSON。
// 未知键、缺必填、枚举外取值和超长字符串都拒绝；值只允许字符串，
// null／数字／布尔／对象／数组一律拒绝（顶层 null 得到的 nil map 同样拒绝）。
// 空对象 {} 合法：全部字段非必填的编组可以显式申报空值。
func validateFieldValues(def *model.FieldGroupDefinition, raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > fieldGroupValuesMaxByte {
		return "", ErrInvalidFieldValues
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return "", ErrInvalidFieldValues
	}
	if values == nil {
		return "", ErrInvalidFieldValues
	}
	known := map[string]*model.FieldGroupField{}
	for i := range def.Fields {
		known[def.Fields[i].Key] = &def.Fields[i]
	}
	for key, value := range values {
		field, ok := known[key]
		if !ok {
			return "", ErrInvalidFieldValues
		}
		text, ok := value.(string)
		if !ok || utf8.RuneCountInString(text) > fieldGroupValueMaxRunes {
			return "", ErrInvalidFieldValues
		}
		if field.Type == "enum" && !containsString(field.Options, text) {
			return "", ErrInvalidFieldValues
		}
		if field.Type == "string" && utf8.RuneCountInString(text) > field.MaxLen {
			return "", ErrInvalidFieldValues
		}
	}
	for i := range def.Fields {
		field := &def.Fields[i]
		value, present := values[field.Key]
		text, _ := value.(string)
		if field.Required && (!present || strings.TrimSpace(text) == "") {
			return "", ErrInvalidFieldValues
		}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	builder.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			builder.WriteByte(',')
		}
		k, _ := json.Marshal(key)
		v, _ := json.Marshal(values[key])
		builder.Write(k)
		builder.WriteByte(':')
		builder.Write(v)
	}
	builder.WriteByte('}')
	return builder.String(), nil
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

const fieldGroupSelect = `SELECT f.id,f.server_id,f.name,f.description,f.definition,f.created_by,f.created_at,f.updated_at,s.name,u.display_name FROM server_field_groups f JOIN trusted_servers s ON s.id=f.server_id JOIN users u ON u.id=f.created_by`

func scanFieldGroup(row interface{ Scan(...any) error }) (*model.FieldGroup, error) {
	var f model.FieldGroup
	var created, updated int64
	err := row.Scan(&f.ID, &f.ServerID, &f.Name, &f.Description, &f.Definition, &f.CreatedBy, &created, &updated, &f.ServerName, &f.CreatorName)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f.CreatedAt, f.UpdatedAt = trustTime(created), trustTime(updated)
	return &f, nil
}

func (s *Store) ListFieldGroups(ctx context.Context, serverID string) ([]*model.FieldGroup, error) {
	rows, err := s.db.QueryContext(ctx, fieldGroupSelect+` WHERE f.server_id=? ORDER BY f.created_at,f.id`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.FieldGroup{}
	for rows.Next() {
		f, e := scanFieldGroup(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) GetFieldGroup(ctx context.Context, id string) (*model.FieldGroup, error) {
	return scanFieldGroup(s.db.QueryRowContext(ctx, fieldGroupSelect+` WHERE f.id=?`, id))
}

// SaveFieldGroup 在服务登记下登记变量编组；一个Server可保存多个编组，
// 不为编组创建新的Server身份。v1 仅支持新增，定义变更通过新编组表达。
func (s *Store) SaveFieldGroup(ctx context.Context, f *model.FieldGroup) error {
	if _, err := s.GetTrustedServer(ctx, f.ServerID); err != nil {
		return ErrInvalidTrust
	}
	f.Name = strings.TrimSpace(f.Name)
	f.Description = strings.TrimSpace(f.Description)
	canonical, _, err := parseFieldGroupDefinition(f.Definition)
	if err != nil {
		return err
	}
	if f.Name == "" || utf8.RuneCountInString(f.Name) > 64 || utf8.RuneCountInString(f.Description) > 500 {
		return ErrInvalidTrust
	}
	at := s.Now().Unix()
	_, err = s.db.ExecContext(ctx, `INSERT INTO server_field_groups(id,server_id,name,description,definition,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, f.ID, f.ServerID, f.Name, f.Description, canonical, f.CreatedBy, at, at)
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err == nil {
		f.Definition = canonical
		f.CreatedAt, f.UpdatedAt = trustTime(at), trustTime(at)
	}
	return err
}

// ---- 临时授信 ----

const grantSelect = `SELECT g.id,g.user_id,g.credential_id,g.server_id,g.parent_token_hash,g.target_origin,g.token_hash,g.token_hint,g.issued_by,g.issued_at,g.expires_at,g.revoked_at,g.last_checked_at,u.display_name,a.name,s.name,i.display_name,COALESCE(gr.name,''),COALESCE(g.group_id,''),g.group_values,g.group_snapshot FROM temporary_grants g JOIN users u ON u.id=g.user_id JOIN agents a ON a.id=g.credential_id JOIN trusted_servers s ON s.id=g.server_id JOIN users i ON i.id=g.issued_by LEFT JOIN server_field_groups gr ON gr.id=g.group_id`

func scanGrant(row interface{ Scan(...any) error }) (*model.TemporaryGrant, error) {
	var g model.TemporaryGrant
	var issued, expires, revoked, checked int64
	err := row.Scan(&g.ID, &g.UserID, &g.CredentialID, &g.ServerID, &g.ParentTokenHash, &g.TargetOrigin, &g.TokenHash, &g.TokenHint, &g.IssuedBy, &issued, &expires, &revoked, &checked, &g.UserName, &g.CredentialName, &g.ServerName, &g.IssuerName, &g.GroupName, &g.GroupID, &g.GroupValues, &g.GroupSnapshot)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.IssuedAt, g.ExpiresAt, g.RevokedAt, g.LastCheckedAt = trustTime(issued), trustTime(expires), trustTime(revoked), trustTime(checked)
	return &g, nil
}

func (s *Store) ListTemporaryGrants(ctx context.Context, owner string) ([]*model.TemporaryGrant, error) {
	query := grantSelect
	args := []any{}
	if owner != "" {
		query += ` WHERE g.user_id=?`
		args = append(args, owner)
	}
	rows, err := s.db.QueryContext(ctx, query+` ORDER BY g.issued_at DESC,g.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.TemporaryGrant{}
	for rows.Next() {
		g, e := scanGrant(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GetTemporaryGrant(ctx context.Context, id string) (*model.TemporaryGrant, error) {
	return scanGrant(s.db.QueryRowContext(ctx, grantSelect+` WHERE g.id=?`, id))
}

// IssueTemporaryGrant 在同一事务内复核归属、状态与范围后签发。
// 有效期由服务端固定为 model.TemporaryGrantTTL（300秒），调用方传入的
// 到期时间一律被覆盖；申报编组时校验归属与取值并保存定义快照。
func (s *Store) IssueTemporaryGrant(ctx context.Context, g *model.TemporaryGrant) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var owner, hash, credentialStatus, userStatus, origin, serverStatus, environment string
		err := tx.QueryRowContext(ctx, `SELECT a.owner_user_id,a.token_hash,a.status,u.status,s.origin,s.status,s.environment FROM agents a JOIN users u ON u.id=a.owner_user_id CROSS JOIN trusted_servers s WHERE a.id=? AND s.id=?`, g.CredentialID, g.ServerID).Scan(&owner, &hash, &credentialStatus, &userStatus, &origin, &serverStatus, &environment)
		if err != nil {
			return ErrInvalidTrust
		}
		if owner != g.UserID || credentialStatus != "active" || userStatus != "active" || serverStatus != "active" || (g.ParentTokenHash != "" && g.ParentTokenHash != hash) {
			return ErrInvalidTrust
		}
		// Agent 请求声明的目标必须在签发事务中复核，避免读取服务后发生配置变更，
		// 导致凭证被悄悄绑定到调用者未申请的地址。管理员网页按服务 ID 签发。
		if g.TargetOrigin != "" && g.TargetOrigin != origin {
			return ErrInvalidTrust
		}
		at := s.Now()
		// 固定300秒：不是默认值，是唯一合法期限，时间以服务端为准。
		g.ExpiresAt = at.Add(model.TemporaryGrantTTL)
		if g.GroupID != "" {
			var groupServer, groupName, definition string
			err := tx.QueryRowContext(ctx, `SELECT server_id,name,definition FROM server_field_groups WHERE id=?`, g.GroupID).Scan(&groupServer, &groupName, &definition)
			if err == sql.ErrNoRows || err == nil && groupServer != g.ServerID {
				return ErrInvalidFieldGroup
			}
			if err != nil {
				return err
			}
			_, def, err := parseFieldGroupDefinition(definition)
			if err != nil {
				return err
			}
			canonical, err := validateFieldValues(def, g.GroupValues)
			if err != nil {
				return err
			}
			g.GroupValues = canonical
			g.GroupSnapshot = definition
			// 签发响应与后续核验返回一致的编组关联信息。
			g.GroupName = groupName
		} else if strings.TrimSpace(g.GroupValues) != "" {
			return ErrInvalidFieldValues
		}
		code, err := workDenial(ctx, tx, owner, g.CredentialID, g.ServerID, environment, at)
		if err != nil {
			return err
		}
		if code != "" {
			return ErrInvalidTrust
		}
		g.IssuedAt = at
		g.ParentTokenHash = hash
		g.TargetOrigin = origin
		_, err = tx.ExecContext(ctx, `INSERT INTO temporary_grants(id,user_id,credential_id,server_id,parent_token_hash,target_origin,token_hash,token_hint,issued_by,issued_at,expires_at,group_id,group_values,group_snapshot) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, g.ID, g.UserID, g.CredentialID, g.ServerID, hash, origin, g.TokenHash, g.TokenHint, g.IssuedBy, at.Unix(), g.ExpiresAt.Unix(), nullStr(g.GroupID), g.GroupValues, g.GroupSnapshot)
		return err
	})
}

func (s *Store) RevokeTemporaryGrant(ctx context.Context, id, actor, owner string) error {
	query := `UPDATE temporary_grants SET revoked_at=?,revoked_by=? WHERE id=? AND revoked_at=0`
	args := []any{s.Now().Unix(), actor, id}
	if owner != "" {
		query += ` AND user_id=?`
		args = append(args, owner)
	}
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const banSelect = `SELECT b.id,b.kind,b.name,COALESCE(b.user_id,''),COALESCE(b.credential_id,''),COALESCE(b.server_id,''),b.environment,b.reason,b.created_by,b.starts_at,b.expires_at,b.released_at,COALESCE(u.display_name,''),COALESCE(a.name,''),COALESCE(s.name,''),i.display_name FROM work_bans b LEFT JOIN users u ON u.id=b.user_id LEFT JOIN agents a ON a.id=b.credential_id LEFT JOIN trusted_servers s ON s.id=b.server_id JOIN users i ON i.id=b.created_by`

func scanWorkBan(row interface{ Scan(...any) error }) (*model.WorkBan, error) {
	var b model.WorkBan
	var starts, expires, released int64
	err := row.Scan(&b.ID, &b.Kind, &b.Name, &b.UserID, &b.CredentialID, &b.ServerID, &b.Environment, &b.Reason, &b.CreatedBy, &starts, &expires, &released, &b.UserName, &b.CredentialName, &b.ServerName, &b.CreatorName)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.StartsAt, b.ExpiresAt, b.ReleasedAt = trustTime(starts), trustTime(expires), trustTime(released)
	return &b, nil
}

func (s *Store) ListWorkBans(ctx context.Context) ([]*model.WorkBan, error) {
	rows, err := s.db.QueryContext(ctx, banSelect+` ORDER BY b.starts_at DESC,b.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.WorkBan{}
	for rows.Next() {
		b, e := scanWorkBan(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (s *Store) GetWorkBan(ctx context.Context, id string) (*model.WorkBan, error) {
	return scanWorkBan(s.db.QueryRowContext(ctx, banSelect+` WHERE b.id=?`, id))
}

func (s *Store) SaveWorkBan(ctx context.Context, b *model.WorkBan, edit bool) error {
	if b.UserID != "" {
		if _, err := s.GetUserByID(ctx, b.UserID); err != nil {
			if err == ErrNotFound {
				return ErrInvalidTrust
			}
			return err
		}
	}
	if b.ServerID != "" {
		if _, err := s.GetTrustedServer(ctx, b.ServerID); err != nil {
			if err == ErrNotFound {
				return ErrInvalidTrust
			}
			return err
		}
	}
	if (b.Kind != "person" && b.Kind != "credential" && b.Kind != "condition") || b.Name == "" || b.Reason == "" || (!b.ExpiresAt.IsZero() && !b.ExpiresAt.After(b.StartsAt)) {
		return ErrInvalidTrust
	}
	if b.Kind == "person" && (b.UserID == "" || b.CredentialID != "" || b.ServerID != "" || b.Environment != "") {
		return ErrInvalidTrust
	}
	if b.Kind == "credential" && (b.CredentialID == "" || b.ServerID != "" || b.Environment != "") {
		return ErrInvalidTrust
	}
	if b.CredentialID != "" {
		a, e := s.GetAgentCredentialByID(ctx, b.CredentialID)
		if e != nil || b.UserID != "" && a.OwnerUserID != b.UserID {
			return ErrInvalidTrust
		}
	}
	args := []any{b.Name, nullStr(b.UserID), nullStr(b.CredentialID), nullStr(b.ServerID), b.Environment, b.Reason, b.StartsAt.Unix(), trustUnix(b.ExpiresAt)}
	var err error
	if edit {
		args = append(args, b.ID)
		var res sql.Result
		res, err = s.db.ExecContext(ctx, `UPDATE work_bans SET name=?,user_id=?,credential_id=?,server_id=?,environment=?,reason=?,starts_at=?,expires_at=? WHERE id=? AND kind='condition' AND released_at=0`, args...)
		if err == nil {
			n, _ := res.RowsAffected()
			if n == 0 {
				return ErrNotFound
			}
		}
	} else {
		args = append(args, b.ID, b.Kind, b.CreatedBy)
		_, err = s.db.ExecContext(ctx, `INSERT INTO work_bans(name,user_id,credential_id,server_id,environment,reason,starts_at,expires_at,id,kind,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, args...)
	}
	return err
}

func (s *Store) ReleaseWorkBan(ctx context.Context, id, actor string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE work_bans SET released_at=?,released_by=? WHERE id=? AND released_at=0`, s.Now().Unix(), actor, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func holiday(ctx context.Context, q trustQuery) (*model.HolidayPlan, error) {
	var p model.HolidayPlan
	var trigger, lock, ends, unlocked int64
	err := q.QueryRowContext(ctx, `SELECT id,created_by,reason,trigger_at,lock_at,ends_at,unlocked_at,observed_state FROM holiday_plans ORDER BY rowid DESC LIMIT 1`).Scan(&p.ID, &p.CreatedBy, &p.Reason, &trigger, &lock, &ends, &unlocked, &p.ObservedState)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.TriggerAt, p.LockAt, p.EndsAt, p.UnlockedAt = trustTime(trigger), trustTime(lock), trustTime(ends), trustTime(unlocked)
	return &p, nil
}
func observeHoliday(ctx context.Context, q trustQuery, at time.Time) (*model.HolidayPlan, error) {
	p, err := holiday(ctx, q)
	if err != nil || p == nil {
		return p, err
	}
	state := p.State(at)
	if state != p.ObservedState {
		res, err := q.ExecContext(ctx, `UPDATE holiday_plans SET observed_state=? WHERE id=? AND observed_state=?`, state, p.ID, p.ObservedState)
		if err != nil {
			return nil, err
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			_, err = q.ExecContext(ctx, `INSERT INTO audit_logs(created_at,event,outcome,detail) VALUES(?,?,?,?)`, fmtTime(at), "holiday_"+state, "success", "plan_id="+p.ID+" observed_state="+state)
			if err != nil {
				return nil, err
			}
		}
	}
	return p, nil
}
func (s *Store) Holiday(ctx context.Context) (*model.HolidayPlan, error) {
	var p *model.HolidayPlan
	err := s.withTx(ctx, func(tx *sql.Tx) error { var e error; p, e = observeHoliday(ctx, tx, s.Now()); return e })
	return p, err
}

func (s *Store) CreateHoliday(ctx context.Context, p *model.HolidayPlan) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		at := s.Now()
		if p.TriggerAt.Before(at) || !p.EndsAt.After(p.TriggerAt.Add(10*time.Second)) {
			return ErrInvalidTrust
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM holiday_plans WHERE unlocked_at=0 AND ends_at>?`, at.Unix()).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return ErrConflict
		}
		p.LockAt = p.TriggerAt.Add(10 * time.Second)
		_, err := tx.ExecContext(ctx, `INSERT INTO holiday_plans(id,created_by,reason,trigger_at,lock_at,ends_at) VALUES(?,?,?,?,?,?)`, p.ID, p.CreatedBy, p.Reason, p.TriggerAt.Unix(), p.LockAt.Unix(), p.EndsAt.Unix())
		return err
	})
}
func (s *Store) UnlockHoliday(ctx context.Context, id, actor string) error {
	at := s.Now().Unix()
	res, err := s.db.ExecContext(ctx, `UPDATE holiday_plans SET unlocked_at=?,unlocked_by=? WHERE id=? AND unlocked_at=0 AND trigger_at<=? AND ends_at>?`, at, actor, id, at, at)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func workDenial(ctx context.Context, q trustQuery, user, credential, server, environment string, at time.Time) (string, error) {
	p, err := observeHoliday(ctx, q, at)
	if err != nil {
		return "", err
	}
	if p.State(at) == "active" {
		return "holiday_lockdown", nil
	}
	rows, err := q.QueryContext(ctx, `SELECT kind FROM work_bans WHERE released_at=0 AND starts_at<=? AND (expires_at=0 OR expires_at>?) AND (user_id IS NULL OR user_id=?) AND (credential_id IS NULL OR credential_id=?) AND (server_id IS NULL OR server_id=?) AND (environment='' OR environment=?) ORDER BY CASE kind WHEN 'person' THEN 1 WHEN 'credential' THEN 2 ELSE 3 END LIMIT 1`, at.Unix(), at.Unix(), user, credential, server, environment)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if rows.Next() {
		var kind string
		if err := rows.Scan(&kind); err != nil {
			return "", err
		}
		return map[string]string{"person": "person_banned", "credential": "credential_banned", "condition": "conditional_banned"}[kind], nil
	}
	return "", rows.Err()
}
func (s *Store) WorkDenial(ctx context.Context, user, credential, server, environment string) (string, error) {
	var code string
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var e error
		code, e = workDenial(ctx, tx, user, credential, server, environment, s.Now())
		return e
	})
	return code, err
}

// grantDenial 读取父凭证当前代次与服务当前配置；每次核验都重新判断。
// 到期判断使用 EffectiveExpiresAt：固定300秒规则同样收口存量长授信。
func grantDenial(ctx context.Context, q trustQuery, g *model.TemporaryGrant, at time.Time) (string, error) {
	if !g.RevokedAt.IsZero() {
		return "grant_revoked", nil
	}
	if at.Before(g.IssuedAt) || !at.Before(g.EffectiveExpiresAt()) {
		return "grant_not_effective", nil
	}
	var hash, status, userStatus, origin, serverStatus, environment string
	err := q.QueryRowContext(ctx, `SELECT a.token_hash,a.status,u.status,s.origin,s.status,s.environment FROM agents a JOIN users u ON u.id=a.owner_user_id CROSS JOIN trusted_servers s WHERE a.id=? AND a.owner_user_id=? AND s.id=?`, g.CredentialID, g.UserID, g.ServerID).Scan(&hash, &status, &userStatus, &origin, &serverStatus, &environment)
	if err != nil {
		return "", err
	}
	if status != "active" || userStatus != "active" || hash != g.ParentTokenHash {
		return "parent_credential_invalid", nil
	}
	if serverStatus != "active" {
		return "server_disabled", nil
	}
	if origin != g.TargetOrigin {
		return "grant_scope_mismatch", nil
	}
	return workDenial(ctx, q, g.UserID, g.CredentialID, g.ServerID, environment, at)
}
func (s *Store) GrantDenial(ctx context.Context, g *model.TemporaryGrant) (string, error) {
	var code string
	err := s.withTx(ctx, func(tx *sql.Tx) error { var e error; code, e = grantDenial(ctx, tx, g, s.Now()); return e })
	return code, err
}

// IntrospectGrant 将服务认证、目标匹配与当前封禁判定放在同一事务快照中。
// 返回（授信, 发起核验的ServerID, 拒绝码, 错误）；拒绝码非空表示不放行。
// 跨Server等已知授信的拒绝保留完整授信记录，供审计关联所属人与凭证，
// 公开响应仍由调用方只回拒绝码，不泄露主体身份。
func (s *Store) IntrospectGrant(ctx context.Context, serverHash, temporaryHash string) (*model.TemporaryGrant, string, string, error) {
	var result *model.TemporaryGrant
	var requesting, code string
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		v, err := scanServer(tx.QueryRowContext(ctx, serverSelect+` WHERE s.token_hash=?`, serverHash))
		if err == ErrNotFound {
			code = "unauthorized"
			return nil
		}
		if err != nil {
			return err
		}
		requesting = v.ID
		if v.Status != "active" {
			result = &model.TemporaryGrant{ServerID: v.ID}
			code = "server_disabled"
			return nil
		}
		g, err := scanGrant(tx.QueryRowContext(ctx, grantSelect+` WHERE g.token_hash=?`, temporaryHash))
		if err == ErrNotFound {
			code = "credential_invalid"
			return nil
		}
		if err != nil {
			return err
		}
		if g.ServerID != v.ID {
			// 保留已知授信的完整链路用于审计；调用方仅向外部返回拒绝码。
			result = g
			code = "grant_scope_mismatch"
			return nil
		}
		result = g
		code, err = grantDenial(ctx, tx, g, s.Now())
		if err != nil {
			return err
		}
		if code != "" {
			return nil
		}
		_, err = tx.ExecContext(ctx, `UPDATE temporary_grants SET last_checked_at=? WHERE id=?`, s.Now().Unix(), g.ID)
		if err == nil {
			result = g
		}
		return err
	})
	return result, requesting, code, err
}

// FormatFieldGroupValues 把编组申报值 JSON 转为 map，供页面与核验响应展示。
func FormatFieldGroupValues(raw string) map[string]string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	var values map[string]string
	if err := json.Unmarshal([]byte(trimmed), &values); err != nil {
		return nil
	}
	return values
}
