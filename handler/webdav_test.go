package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebDavAuth(t *testing.T) {
	wh := NewWebDavHandler(t.TempDir(), "user", "pass")

	tests := []struct {
		name       string
		username   string
		password   string
		wantStatus int
	}{
		{name: "no credentials", wantStatus: http.StatusUnauthorized},
		{name: "wrong username", username: "wrong", password: "pass", wantStatus: http.StatusUnauthorized},
		{name: "wrong password", username: "user", password: "wrong", wantStatus: http.StatusUnauthorized},
		{name: "correct credentials", username: "user", password: "pass", wantStatus: http.StatusMultiStatus},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := serveWebDav(wh, tt.username, tt.password)
			if rr.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusUnauthorized && rr.Header().Get("WWW-Authenticate") == "" {
				t.Fatal("WWW-Authenticate header is missing")
			}
		})
	}
}

func TestWebDavAuthRateLimit(t *testing.T) {
	wh := NewWebDavHandler(t.TempDir(), "user", "pass")
	wh.SetAuthLimit(2, time.Minute)

	// 未携带凭据属于正常的 Basic Auth 挑战流程，不应计入失败次数
	for i := 0; i < 5; i++ {
		rr := serveWebDav(wh, "", "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("no-credential request %d status = %d, want %d", i+1, rr.Code, http.StatusUnauthorized)
		}
	}

	// 两次错误凭据后达到上限
	for i := 0; i < 2; i++ {
		rr := serveWebDav(wh, "user", "wrong")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("wrong-credential request %d status = %d, want %d", i+1, rr.Code, http.StatusUnauthorized)
		}
	}

	rr := serveWebDav(wh, "user", "wrong")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header is missing")
	}

	// 未携带凭据仍然返回 401 挑战，而不是 429
	rr = serveWebDav(wh, "", "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-credential status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	// 正确凭据不受同一 IP 上他人失败尝试的影响，并会重置计数
	rr = serveWebDav(wh, "user", "pass")
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("correct-credential status = %d, want %d", rr.Code, http.StatusMultiStatus)
	}

	// 重置后错误凭据重新从 401 开始计数
	rr = serveWebDav(wh, "user", "wrong")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func serveWebDav(wh *WebDavHandler, username, password string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PROPFIND", "/webdav/", nil)
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	rr := httptest.NewRecorder()
	wh.ServeHTTP(rr, req)
	return rr
}
