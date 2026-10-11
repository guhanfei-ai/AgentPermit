package handler

import (
	"sync"
	"time"
)

// Limiter 是单进程内存滑动窗口限流器。
// 仅适用于单实例部署；多实例需要分布式限流（第一版明确不做，也不为此引入 Redis）。
type Limiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	limit  int
	window time.Duration
}

// NewLimiter 默认 60 秒窗口。
func NewLimiter() *Limiter {
	return &Limiter{hits: map[string][]time.Time{}, limit: 10, window: time.Minute}
}

// Allow 判断 key 在默认窗口（60 秒 10 次）内是否仍允许一次请求。
func (l *Limiter) Allow(key string) bool {
	return l.AllowWindow(key, l.limit, l.window)
}

// AllowWindow 使用自定义窗口与阈值判断（授权接口等服务间调用使用更高阈值）。
func (l *Limiter) AllowWindow(key string, limit int, window time.Duration) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	times := l.hits[key]
	keep := times[:0]
	for _, t := range times {
		if now.Sub(t) < window {
			keep = append(keep, t)
		}
	}
	if len(keep) >= limit {
		l.hits[key] = keep
		return false
	}
	l.hits[key] = append(keep, now)
	// 防止 map 无限增长：超过一定规模时清理空键
	if len(l.hits) > 10000 {
		for k, v := range l.hits {
			if len(v) == 0 {
				delete(l.hits, k)
			}
		}
	}
	return true
}
