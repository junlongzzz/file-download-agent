package handler

import (
	"sync"
	"time"
)

const (
	// 默认同一客户端在一个窗口期内允许的认证失败次数
	defaultMaxAuthFailures = 10
	// 默认失败计数窗口，达到上限后在该窗口内拒绝继续尝试
	defaultAuthFailureWindow = time.Minute
	// 限制记录数量，避免大量不同来源耗尽内存
	maxAuthFailureEntries = 4096
	// 单个客户端同时进行的昂贵解密尝试上限。并发请求可能在失败计数
	// 落库前全部通过检查，这里限制进行中的数量，全局 KDF 信号量再把
	// 实际并行度限制在 4。
	maxConcurrentEncAttempts = 16
)

// authFailureLimiter 按客户端限制认证失败次数，避免通过接口在线撞库。
type authFailureLimiter struct {
	mu          sync.Mutex
	entries     map[string]*authFailureEntry
	maxFailures int
	window      time.Duration
	now         func() time.Time // 便于测试时替换时钟
}

type authFailureEntry struct {
	failures int       // 窗口期内的失败次数
	inFlight int       // 已放行但尚未结束的昂贵尝试数
	resetAt  time.Time // 窗口结束时间
}

func newAuthFailureLimiter(maxFailures int, window time.Duration) *authFailureLimiter {
	if maxFailures < 1 {
		maxFailures = defaultMaxAuthFailures
	}
	if window <= 0 {
		window = defaultAuthFailureWindow
	}
	return &authFailureLimiter{
		entries:     make(map[string]*authFailureEntry),
		maxFailures: maxFailures,
		window:      window,
		now:         time.Now,
	}
}

// blocked 返回剩余禁用时间和是否已被禁用。
func (l *authFailureLimiter) blocked(key string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry, ok := l.entries[key]
	if !ok {
		return 0, false
	}
	if !now.Before(entry.resetAt) {
		delete(l.entries, key)
		return 0, false
	}
	if entry.failures >= l.maxFailures {
		return entry.resetAt.Sub(now), true
	}
	return 0, false
}

// entryLocked 返回 key 在当前窗口内的记录，必要时创建或淘汰旧记录。
// 调用方必须持有 l.mu。
func (l *authFailureLimiter) entryLocked(key string, now time.Time) *authFailureEntry {
	if entry, ok := l.entries[key]; ok {
		if now.Before(entry.resetAt) {
			return entry
		}
		delete(l.entries, key)
	}
	// 达到容量上限时先清理过期记录；仍然满则淘汰任意一条窗口内的记录，
	// 为新来源腾出位置。若直接返回，新 key 将永远不会被计数，
	// 攻击者只要不断更换来源就能绕过限流（fail-open）。
	if len(l.entries) >= maxAuthFailureEntries {
		l.cleanupLocked(now)
		if len(l.entries) >= maxAuthFailureEntries {
			for oldestKey := range l.entries {
				delete(l.entries, oldestKey)
				break
			}
		}
	}
	entry := &authFailureEntry{resetAt: now.Add(l.window)}
	l.entries[key] = entry
	return entry
}

// recordFailureLocked 记录一次失败，调用方必须持有 l.mu。
func (l *authFailureLimiter) recordFailureLocked(entry *authFailureEntry, now time.Time) {
	entry.failures++
	if entry.failures == l.maxFailures {
		// 达到上限后从当前时刻重新计时，确保完整的禁用窗口
		entry.resetAt = now.Add(l.window)
	}
}

// fail 记录一次认证失败。
func (l *authFailureLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.recordFailureLocked(l.entryLocked(key, now), now)
}

// beginAttempt 检查是否允许发起一次昂贵的解密尝试，并计入进行中数量。
// 返回 false 表示已被限流，或同一客户端的并发尝试达到上限。
func (l *authFailureLimiter) beginAttempt(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.entryLocked(key, l.now())
	if entry.failures >= l.maxFailures || entry.inFlight >= maxConcurrentEncAttempts {
		return false
	}
	entry.inFlight++
	return true
}

// finishAttempt 结束一次 beginAttempt。failed 为 true 时记录一次失败，
// 否则释放并发名额；没有历史失败的空记录会立即删除。
func (l *authFailureLimiter) finishAttempt(key string, failed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok {
		return
	}
	if entry.inFlight > 0 {
		entry.inFlight--
	}
	if failed {
		l.recordFailureLocked(entry, l.now())
		return
	}
	if entry.failures == 0 && entry.inFlight == 0 {
		delete(l.entries, key)
	}
}

// reset 在认证成功后清除该客户端的失败记录。
func (l *authFailureLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

func (l *authFailureLimiter) cleanupLocked(now time.Time) {
	for key, entry := range l.entries {
		if !now.Before(entry.resetAt) {
			delete(l.entries, key)
		}
	}
}

// retryAfterSeconds 将剩余时间向上取整为秒，最小为 1。
func retryAfterSeconds(d time.Duration) int {
	seconds := int((d + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
