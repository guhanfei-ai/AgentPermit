package handler

import (
	"net/http"

	"agentpermit/internal/model"
	"agentpermit/internal/policy"
	"agentpermit/internal/store"
)

// CatalogItem 是人类能力广场的展示项。
type CatalogItem struct {
	Capability       *model.Capability
	Latest           *model.CapabilityVersion
	OwnerUsername    string
	OwnerDisplayName string
	IsOwner          bool
}

// evaluateForUser 对登录用户评估能力可访问性（集中走 policy 包）。
func (s *Server) evaluateForUser(r *http.Request, u *model.User, c *model.Capability) (policy.Decision, error) {
	ctx := r.Context()
	capOwner, err := s.store.GetUserByID(ctx, c.OwnerUserID)
	if err != nil {
		return policy.Decision{}, err
	}
	denied, err := s.store.IsDenied(ctx, c.ID, u.ID)
	if err != nil {
		return policy.Decision{}, err
	}
	allowlisted, err := s.store.IsAllowlisted(ctx, c.ID, u.ID)
	if err != nil {
		return policy.Decision{}, err
	}
	return policy.EvaluateForUser(u, policy.Input{
		Capability:  c,
		CapOwner:    capOwner,
		Denied:      denied,
		Allowlisted: allowlisted,
	}), nil
}

func (s *Server) pageCatalog(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	caps, err := s.store.ListAllCapabilities(r.Context())
	if err != nil {
		s.logger.Error("查询能力失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	ownerCache := map[string]*model.User{}
	items := []*CatalogItem{}
	for _, c := range caps {
		owner, ok := ownerCache[c.OwnerUserID]
		if !ok {
			owner, err = s.store.GetUserByID(r.Context(), c.OwnerUserID)
			if err != nil {
				s.logger.Error("查询能力所有者失败", "err", err)
				continue
			}
			ownerCache[c.OwnerUserID] = owner
		}
		dec, err := s.evaluateForUser(r, u, c)
		if err != nil {
			s.logger.Error("策略评估失败", "err", err)
			continue
		}
		if dec.Allowed {
			latest, err := s.store.GetCapabilityLatestSnapshot(r.Context(), c.ID)
			if err != nil {
				s.logger.Error("查询发布版本失败", "err", err, "capability_id", c.ID)
				continue
			}
			items = append(items, &CatalogItem{
				Capability:       c,
				Latest:           latest,
				OwnerUsername:    owner.Username,
				OwnerDisplayName: owner.DisplayName,
				IsOwner:          owner.ID == u.ID,
			})
		}
	}
	s.renderPage(w, r, http.StatusOK, "catalog", "人类能力广场", "catalog", map[string]any{"Catalog": items})
}

func (s *Server) pageCatalogDetail(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r.Context())
	id := r.PathValue("id")
	c, err := s.store.GetCapabilityByID(r.Context(), id)
	if err != nil {
		s.renderError(w, r, http.StatusNotFound, "能力不存在或无权访问。")
		return
	}
	// 详情页同样走集中策略评估，不能通过猜测 ID 绕过
	dec, err := s.evaluateForUser(r, u, c)
	if err != nil {
		s.logger.Error("策略评估失败", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	if !dec.Allowed {
		// 无权与不存在统一 404，避免泄露存在性
		s.renderError(w, r, http.StatusNotFound, "能力不存在或无权访问。")
		return
	}
	owner, err := s.store.GetUserByID(r.Context(), c.OwnerUserID)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		return
	}
	// 目录展示 latest 发布快照，与 Agent API 看到的内容一致（草稿不外泄）
	latest, err := s.store.GetCapabilityLatestSnapshot(r.Context(), c.ID)
	if err != nil {
		if err == store.ErrNotFound {
			s.renderError(w, r, http.StatusNotFound, "能力尚无可读取的发布版本。")
		} else {
			s.logger.Error("查询发布版本失败", "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "服务暂时不可用。")
		}
		return
	}
	s.renderPage(w, r, http.StatusOK, "catalog_detail", latest.Name, "catalog", map[string]any{
		"Capability":       c,
		"Latest":           latest,
		"OwnerUsername":    owner.Username,
		"OwnerDisplayName": owner.DisplayName,
		"IsOwner":          owner.ID == u.ID,
	})
}
