package handler

import (
	"strconv"
	"testing"
	"time"
)

func TestAuthFailureLimiterWindow(t *testing.T) {
	now := time.Unix(0, 0)
	limiter := newAuthFailureLimiter(2, time.Minute)
	limiter.now = func() time.Time { return now }

	if _, blocked := limiter.blocked("ip"); blocked {
		t.Fatal("blocked() = true before any failure")
	}

	limiter.fail("ip")
	limiter.fail("ip")
	retryAfter, blocked := limiter.blocked("ip")
	if !blocked {
		t.Fatal("blocked() = false after reaching max failures")
	}
	if retryAfter <= 0 || retryAfter > time.Minute {
		t.Fatalf("retryAfter = %s, want within (0, 1m]", retryAfter)
	}

	// 窗口结束后应自动解除限制
	now = now.Add(time.Minute)
	if _, blocked := limiter.blocked("ip"); blocked {
		t.Fatal("blocked() = true after window expired")
	}
}

// 容量满时新来源仍要被计数，不能因为无处存放就直接放行。
func TestAuthFailureLimiterEvictsWhenFull(t *testing.T) {
	now := time.Unix(0, 0)
	limiter := newAuthFailureLimiter(1, time.Minute)
	limiter.now = func() time.Time { return now }

	// 直接填满内部表，模拟大量不同来源
	for i := 0; i < maxAuthFailureEntries; i++ {
		limiter.entries[strconv.Itoa(i)] = &authFailureEntry{resetAt: now.Add(time.Minute)}
	}

	limiter.fail("new-key")
	if _, blocked := limiter.blocked("new-key"); !blocked {
		t.Fatal("new key was not counted when the limiter was full")
	}
	if len(limiter.entries) > maxAuthFailureEntries {
		t.Fatalf("entries = %d, want <= %d", len(limiter.entries), maxAuthFailureEntries)
	}
}

// 并发突刺不能绕过失败计数：同一客户端同时进行的解密尝试有上限。
func TestAuthFailureLimiterConcurrentAttempts(t *testing.T) {
	limiter := newAuthFailureLimiter(100, time.Minute)

	for i := 0; i < maxConcurrentEncAttempts; i++ {
		if !limiter.beginAttempt("ip") {
			t.Fatalf("beginAttempt() = false at attempt %d", i+1)
		}
	}
	if limiter.beginAttempt("ip") {
		t.Fatal("beginAttempt() = true beyond the concurrency cap")
	}

	// 成功的尝试会释放名额，没有历史失败的空记录会被删除
	for i := 0; i < maxConcurrentEncAttempts; i++ {
		limiter.finishAttempt("ip", false)
	}
	if _, exists := limiter.entries["ip"]; exists {
		t.Fatal("empty entry was not removed after successful attempts")
	}
	if !limiter.beginAttempt("ip") {
		t.Fatal("beginAttempt() = false after slots were released")
	}
}

// 失败尝试在结束时记账，达到上限后不再放行新的尝试。
func TestAuthFailureLimiterConcurrentFailures(t *testing.T) {
	limiter := newAuthFailureLimiter(2, time.Minute)

	if !limiter.beginAttempt("ip") || !limiter.beginAttempt("ip") {
		t.Fatal("beginAttempt() = false before reaching the failure limit")
	}
	limiter.finishAttempt("ip", true)
	limiter.finishAttempt("ip", true)

	if limiter.beginAttempt("ip") {
		t.Fatal("beginAttempt() = true after reaching the failure limit")
	}
	if _, blocked := limiter.blocked("ip"); !blocked {
		t.Fatal("blocked() = false after reaching the failure limit")
	}
}

func TestAuthFailureLimiterReset(t *testing.T) {
	limiter := newAuthFailureLimiter(1, time.Minute)
	limiter.fail("ip")
	if _, blocked := limiter.blocked("ip"); !blocked {
		t.Fatal("blocked() = false after one failure with max 1")
	}
	limiter.reset("ip")
	if _, blocked := limiter.blocked("ip"); blocked {
		t.Fatal("blocked() = true after reset")
	}
}
