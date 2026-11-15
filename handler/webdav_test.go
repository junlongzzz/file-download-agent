package handler

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestWebDavPathCredentials(t *testing.T) {
	wh := NewWebDavHandler(t.TempDir(), "user", "pass")
	if !wh.PathAuthEnabled() {
		t.Fatal("path authentication should be enabled")
	}
	credential := basicPathCredential("user", "pass")
	if credential != "dXNlcjpwYXNz" {
		t.Fatalf("credential = %q, want dXNlcjpwYXNz", credential)
	}

	// 路径凭据无需 Basic 头
	rr := serveWebDavRequest(wh, "/webdav/"+credential+"/", "", "")
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("path credential request status = %d, want %d", rr.Code, http.StatusMultiStatus)
	}
	// PROPFIND 返回的子资源地址必须带路径凭据，挂载型客户端后续请求才不会掉认证
	if !strings.Contains(rr.Body.String(), "/webdav/"+credential+"/") {
		t.Fatalf("PROPFIND body does not contain credential href: %s", rr.Body.String())
	}
	// 路径中不能出现明文的用户名密码
	if strings.Contains(rr.Body.String(), "user:pass") {
		t.Fatal("plaintext credentials leaked into PROPFIND response")
	}

	// 标准 Basic 认证仍然可用
	if rr := serveWebDav(wh, "user", "pass"); rr.Code != http.StatusMultiStatus {
		t.Fatalf("basic request status = %d, want %d", rr.Code, http.StatusMultiStatus)
	}

	// 路径凭据上同时携带有效 Basic 凭据时仍走路径 handler，不能被当成目录
	rr = serveWebDavRequest(wh, "/webdav/"+credential+"/", "user", "pass")
	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("path credential with basic credentials status = %d, want %d", rr.Code, http.StatusMultiStatus)
	}

	// 错误路径凭据回落到 Basic 挑战
	rr = serveWebDavRequest(wh, "/webdav/"+basicPathCredential("user", "wrong")+"/", "", "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong path credential status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("WWW-Authenticate header is missing")
	}

	// 修改 Basic 凭据后，路径认证入口同步更新
	wh.SetBasicAuth("other", "secret")
	if rr := serveWebDavRequest(wh, "/webdav/"+basicPathCredential("other", "secret")+"/", "", ""); rr.Code != http.StatusMultiStatus {
		t.Fatalf("updated path credential status = %d, want %d", rr.Code, http.StatusMultiStatus)
	}
	if rr := serveWebDavRequest(wh, "/webdav/"+credential+"/", "", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("stale path credential status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestWebDavPathCredentialsResetsAuthFailures(t *testing.T) {
	wh := NewWebDavHandler(t.TempDir(), "user", "pass")
	wh.SetAuthLimit(1, time.Minute)

	// 先用错误 Basic 凭据触发限流
	if rr := serveWebDav(wh, "user", "wrong"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-credential status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	// 正确的路径凭据不受影响，并重置计数
	if rr := serveWebDavRequest(wh, "/webdav/"+basicPathCredential("user", "pass")+"/", "", ""); rr.Code != http.StatusMultiStatus {
		t.Fatalf("path credential request status = %d, want %d", rr.Code, http.StatusMultiStatus)
	}
	// 计数已重置，错误 Basic 凭据重新从 401 开始
	if rr := serveWebDav(wh, "user", "wrong"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("post-reset wrong-credential status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestWebDavPathCredentialsSpecialCharacters(t *testing.T) {
	const username = "us#er"
	const password = "pa ss/密码"
	wh := NewWebDavHandler(t.TempDir(), username, password)
	if !wh.PathAuthEnabled() {
		t.Fatal("path authentication should be enabled")
	}

	// base64url 编码后任意凭据都能安全放入路径段
	if rr := serveWebDavRequest(wh, "/webdav/"+basicPathCredential(username, password)+"/", "", ""); rr.Code != http.StatusMultiStatus {
		t.Fatalf("path credential status = %d, want %d", rr.Code, http.StatusMultiStatus)
	}
	// Basic 认证不受影响
	if rr := serveWebDav(wh, username, password); rr.Code != http.StatusMultiStatus {
		t.Fatalf("basic request status = %d, want %d", rr.Code, http.StatusMultiStatus)
	}
}

func serveWebDav(wh *WebDavHandler, username, password string) *httptest.ResponseRecorder {
	return serveWebDavRequest(wh, "/webdav/", username, password)
}

func serveWebDavRequest(wh *WebDavHandler, path, username, password string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PROPFIND", path, nil)
	if username != "" || password != "" {
		req.SetBasicAuth(username, password)
	}
	rr := httptest.NewRecorder()
	wh.ServeHTTP(rr, req)
	return rr
}

func basicPathCredential(username, password string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(username + ":" + password))
}
