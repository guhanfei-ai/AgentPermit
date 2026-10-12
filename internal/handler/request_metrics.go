package handler

import (
	"net/http"
	"sync"
	"time"

	"agentpermit/internal/model"
)

type runtimeValues struct{ requests, duration, peak int64 }
type runtimeBucket struct {
	second   int64
	global   runtimeValues
	accounts map[string]*runtimeValues
}
type apiObservation struct {
	started  time.Time
	accounts map[string]bool
	done     bool
}

// requestMetrics 使用 300 个秒桶；内存只保留最近五分钟的账号聚合与当前请求。
// 不采集 Token、地址、请求体或 Agent 运行实例信息。
type requestMetrics struct {
	mu       sync.Mutex
	now      func() time.Time
	started  time.Time
	current  int64
	accounts map[string]int64
	buckets  [300]runtimeBucket
}

func newRequestMetrics(now func() time.Time) *requestMetrics {
	return &requestMetrics{now: now, started: now(), accounts: map[string]int64{}}
}
func (m *requestMetrics) bucket(now time.Time) *runtimeBucket {
	second := now.Unix()
	b := &m.buckets[second%300]
	if b.second != second {
		*b = runtimeBucket{second: second, accounts: map[string]*runtimeValues{}}
	}
	return b
}
func (b *runtimeBucket) account(id string) *runtimeValues {
	if b.accounts[id] == nil {
		b.accounts[id] = &runtimeValues{}
	}
	return b.accounts[id]
}
func (m *requestMetrics) begin() *apiObservation {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.current++
	b := m.bucket(now)
	if m.current > b.global.peak {
		b.global.peak = m.current
	}
	return &apiObservation{started: now, accounts: map[string]bool{}}
}
func (m *requestMetrics) attribute(o *apiObservation, ids ...string) {
	if o == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if o.done {
		return
	}
	b := m.bucket(m.now())
	for _, id := range ids {
		if id == "" || o.accounts[id] {
			continue
		}
		o.accounts[id] = true
		m.accounts[id]++
		v := b.account(id)
		if m.accounts[id] > v.peak {
			v.peak = m.accounts[id]
		}
	}
}
func (m *requestMetrics) finish(o *apiObservation) {
	if o == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if o.done {
		return
	}
	o.done = true
	now := m.now()
	elapsed := now.Sub(o.started).Nanoseconds()
	if elapsed < 0 {
		elapsed = 0
	}
	b := m.bucket(now)
	if m.current > b.global.peak {
		b.global.peak = m.current
	}
	b.global.requests++
	b.global.duration += elapsed
	m.current--
	for id := range o.accounts {
		v := b.account(id)
		if m.accounts[id] > v.peak {
			v.peak = m.accounts[id]
		}
		v.requests++
		v.duration += elapsed
		m.accounts[id]--
		if m.accounts[id] == 0 {
			delete(m.accounts, id)
		}
	}
}
func (m *requestMetrics) snapshot(userID string, all bool) model.DashboardRuntime {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := model.DashboardRuntime{Current: m.accounts[userID], StartedAt: m.started}
	if all {
		out.Current = m.current
	}
	out.Peak = out.Current
	second := m.now().Unix()
	var duration int64
	for i := range m.buckets {
		b := &m.buckets[i]
		if b.second <= second-300 || b.second > second {
			continue
		}
		v := b.accounts[userID]
		if all {
			v = &b.global
		}
		if v == nil {
			continue
		}
		out.Requests += v.requests
		duration += v.duration
		if v.peak > out.Peak {
			out.Peak = v.peak
		}
	}
	if out.Requests > 0 {
		average := float64(duration) / float64(out.Requests) / 1e6
		out.AverageMS = &average
	}
	return out
}
func (s *Server) bindRuntime(r *http.Request, ids ...string) {
	o, _ := r.Context().Value(ctxAPIObservation).(*apiObservation)
	s.metrics.attribute(o, ids...)
}
