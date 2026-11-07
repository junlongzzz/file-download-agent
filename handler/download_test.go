package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/junlongzzz/file-download-agent/common"
)

func TestPostBodyTooLargeReturns413(t *testing.T) {
	dh := NewDownloadHandler(t.TempDir(), "")
	body := `{"url":"` + strings.Repeat("a", maxPostBodySize) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(body))
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

// 恶意的非 12 字节 nonce 不能让服务 panic，必须返回 400。
func TestDownloadRejectsInvalidEncWithoutPanic(t *testing.T) {
	blob, err := json.Marshal(common.EncryptedData{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(make([]byte, 16)),
		Nonce:   base64.StdEncoding.EncodeToString(make([]byte, 4)),
		Cipher:  base64.StdEncoding.EncodeToString(make([]byte, 16)),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString(blob)

	dh := NewDownloadHandler(t.TempDir(), "secret")
	req := httptest.NewRequest(http.MethodGet, "/download?enc="+url.QueryEscape(enc), nil)
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestDownloadRejectsOversizedEnc(t *testing.T) {
	dh := NewDownloadHandler(t.TempDir(), "secret")
	req := httptest.NewRequest(http.MethodGet, "/download?enc="+strings.Repeat("A", maxEncodedEncLen+1), nil)
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestDownloadRateLimitsInvalidEnc(t *testing.T) {
	dh := NewDownloadHandler(t.TempDir(), "secret")
	dh.SetAuthLimit(2, time.Minute)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/download?enc=e30", nil)
		rr := httptest.NewRecorder()
		dh.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("request %d status = %d, want %d", i+1, rr.Code, http.StatusBadRequest)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/download?enc=e30", nil)
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
}

// 有效的加密链接可以被公开分享，成功解密不能重置 signKey 的失败计数。
func TestDownloadEncSuccessDoesNotResetSignFailures(t *testing.T) {
	dh := NewDownloadHandler(t.TempDir(), "secret")
	dh.SetAuthLimit(2, time.Minute)

	// 先用正确密钥生成一个有效的加密链接
	postReq := httptest.NewRequest(http.MethodPost, "/download",
		strings.NewReader(`{"url":"file:///missing","filename":"missing","sign":"secret"}`))
	postResp := httptest.NewRecorder()
	dh.ServeHTTP(postResp, postReq)
	if postResp.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d", postResp.Code, http.StatusOK)
	}
	var result struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(postResp.Body.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// 两次错误的 POST 密钥把计数打到上限
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/download",
			strings.NewReader(`{"url":"file:///x","sign":"wrong"}`))
		rr := httptest.NewRecorder()
		dh.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("bad key request %d status = %d, want %d", i+1, rr.Code, http.StatusForbidden)
		}
	}

	// 有效加密链接解密成功，不能清空上面的失败计数
	getReq := httptest.NewRequest(http.MethodGet, "/download?enc="+url.QueryEscape(result.Data), nil)
	getResp := httptest.NewRecorder()
	dh.ServeHTTP(getResp, getReq)
	if getResp.Code == http.StatusTooManyRequests {
		t.Fatal("valid enc download must not be blocked by sign failures")
	}

	// 计数仍然处于上限，下一次错误密钥必须被限流
	req := httptest.NewRequest(http.MethodPost, "/download",
		strings.NewReader(`{"url":"file:///x","sign":"wrong"}`))
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}
}

// 明文签名失败不能把同一 IP 的合法加密链接下载一起锁死。
func TestPlainSignFailuresDoNotBlockEncDownloads(t *testing.T) {
	dh := NewDownloadHandler(t.TempDir(), "secret")
	dh.SetAuthLimit(1, time.Minute)

	// 先生成有效加密链接（POST 密钥正确）
	postReq := httptest.NewRequest(http.MethodPost, "/download",
		strings.NewReader(`{"url":"file:///missing","filename":"missing","sign":"secret"}`))
	postResp := httptest.NewRecorder()
	dh.ServeHTTP(postResp, postReq)
	if postResp.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d", postResp.Code, http.StatusOK)
	}
	var result struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(postResp.Body.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// 一次错误的明文签名后，同一 IP 的明文请求被限流
	badSign := "/download?url=" + url.QueryEscape("file:///x") + "&sign=wrong"
	req := httptest.NewRequest(http.MethodGet, badSign, nil)
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("first bad sign status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	req = httptest.NewRequest(http.MethodGet, badSign, nil)
	rr = httptest.NewRecorder()
	dh.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second bad sign status = %d, want %d", rr.Code, http.StatusTooManyRequests)
	}

	// 加密链接使用独立限流器，不受签名失败影响
	getReq := httptest.NewRequest(http.MethodGet, "/download?enc="+url.QueryEscape(result.Data), nil)
	getResp := httptest.NewRecorder()
	dh.ServeHTTP(getResp, getReq)
	if getResp.Code == http.StatusTooManyRequests {
		t.Fatal("enc download must not be blocked by plain signature failures")
	}
}

func TestPostRejectsTooLongGeneratedLink(t *testing.T) {
	dh := NewDownloadHandler(t.TempDir(), "")
	body := `{"url":"https://example.com/` + strings.Repeat("a", maxEncodedEncLen) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(body))
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

// 明文签名用 "|" 拼接，不能通过把 expire 移进 url 来绕过过期校验。
func TestDownloadRejectsPipeInSignedParams(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer upstream.Close()

	dh := NewDownloadHandler(t.TempDir(), "secret", WithAllowPrivateNetwork(true))
	expire := "1700000000" // 已过期
	target := upstream.URL + "/file"
	sign := common.CalculateMD5(strings.Join([]string{target, expire, "secret"}, "|"))

	// 合法签名针对 target|expire|secret；把 expire 拼进 url 并省略 expire，
	// 未修复时签名输入仍然是 target|expire|secret，会绕过过期校验。
	req := httptest.NewRequest(http.MethodGet,
		"/download?url="+url.QueryEscape(target+"|"+expire)+"&sign="+url.QueryEscape(sign), nil)
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestDownloadRejectsPipeInSignedFields(t *testing.T) {
	dh := NewDownloadHandler(t.TempDir(), "secret")
	target := "https://example.com/file"
	tests := []struct {
		name  string
		query string
	}{
		{
			name:  "url",
			query: "/download?url=" + url.QueryEscape(target+"|1700000000") + "&sign=x",
		},
		{
			name:  "filename",
			query: "/download?url=" + url.QueryEscape(target) + "&filename=" + url.QueryEscape("a|b") + "&sign=x",
		},
		{
			name:  "expire",
			query: "/download?url=" + url.QueryEscape(target) + "&expire=" + url.QueryEscape("1|2") + "&sign=x",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.query, nil)
			rr := httptest.NewRecorder()
			dh.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
		})
	}
}

// POST 生成链接、GET 解密下载的完整流程应保持可用。
func TestPostThenGetEncryptedLink(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	}))
	defer upstream.Close()

	dh := NewDownloadHandler(t.TempDir(), "secret", WithAllowPrivateNetwork(true))

	body := `{"url":"` + upstream.URL + `/file.txt","filename":"file.txt","sign":"secret"}`
	postReq := httptest.NewRequest(http.MethodPost, "/download", strings.NewReader(body))
	postResp := httptest.NewRecorder()
	dh.ServeHTTP(postResp, postReq)
	if postResp.Code != http.StatusOK {
		t.Fatalf("POST status = %d, want %d", postResp.Code, http.StatusOK)
	}

	var result struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(postResp.Body.Bytes(), &result); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if result.Data == "" {
		t.Fatal("POST response data is empty")
	}

	getReq := httptest.NewRequest(http.MethodGet, "/download?enc="+url.QueryEscape(result.Data), nil)
	getResp := httptest.NewRecorder()
	dh.ServeHTTP(getResp, getReq)
	if getResp.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want %d", getResp.Code, http.StatusOK)
	}
	if got := getResp.Body.String(); got != "hello world" {
		t.Fatalf("GET body = %q, want %q", got, "hello world")
	}
}

func TestDownloadNotModifiedForwardsCacheHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Content-Length", "1234")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer upstream.Close()

	dh := NewDownloadHandler(t.TempDir(), "",
		WithAllowPrivateNetwork(true),
		WithForwardResponseHeaders([]string{"Cache-Control"}))
	req := httptest.NewRequest(http.MethodGet,
		"/download?url="+url.QueryEscape(upstream.URL+"/file.zip")+"&filename=file.zip", nil)
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotModified)
	}
	if got := rr.Header().Get("Etag"); got != `"abc"` {
		t.Fatalf("Etag = %q, want %q", got, `"abc"`)
	}
	if got := rr.Header().Get("Last-Modified"); got == "" {
		t.Fatal("Last-Modified header was not forwarded")
	}
	if got := rr.Header().Get("Cache-Control"); got != "max-age=60" {
		t.Fatalf("Cache-Control = %q, want %q", got, "max-age=60")
	}
	if got := rr.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want empty", got)
	}
}

func TestDownloadRangeNotSatisfiableForwardsContentRange(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes */1234")
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
	}))
	defer upstream.Close()

	dh := NewDownloadHandler(t.TempDir(), "", WithAllowPrivateNetwork(true))
	req := httptest.NewRequest(http.MethodGet,
		"/download?url="+url.QueryEscape(upstream.URL+"/file.zip")+"&filename=file.zip", nil)
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusRequestedRangeNotSatisfiable)
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes */1234" {
		t.Fatalf("Content-Range = %q, want %q", got, "bytes */1234")
	}
}

// 401 的认证挑战只有在 Authorization 会被转发时才有意义，否则会造成认证循环。
func TestDownloadUnauthorizedChallengeForwarding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="upstream"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	tests := []struct {
		name          string
		opts          []DownloadOption
		wantChallenge bool
	}{
		{
			name: "default does not forward",
		},
		{
			name:          "authorization forwarded",
			opts:          []DownloadOption{WithForwardRequestHeaders([]string{"Authorization"})},
			wantChallenge: true,
		},
		{
			name:          "response header whitelisted",
			opts:          []DownloadOption{WithForwardResponseHeaders([]string{"WWW-Authenticate"})},
			wantChallenge: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := append([]DownloadOption{WithAllowPrivateNetwork(true)}, tt.opts...)
			dh := NewDownloadHandler(t.TempDir(), "", opts...)
			req := httptest.NewRequest(http.MethodGet,
				"/download?url="+url.QueryEscape(upstream.URL+"/file")+"&filename=file", nil)
			rr := httptest.NewRecorder()
			dh.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
			}
			got := rr.Header().Get("WWW-Authenticate")
			if tt.wantChallenge && got != `Basic realm="upstream"` {
				t.Fatalf("WWW-Authenticate = %q, want %q", got, `Basic realm="upstream"`)
			}
			if !tt.wantChallenge && got != "" {
				t.Fatalf("WWW-Authenticate = %q, want empty", got)
			}
		})
	}
}

// 转发 Authorization 后，上游的 Basic Auth 挑战可以真正完成认证。
func TestDownloadUpstreamBasicAuthFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "user" || password != "pass" {
			w.Header().Set("WWW-Authenticate", `Basic realm="upstream"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("authorized"))
	}))
	defer upstream.Close()

	dh := NewDownloadHandler(t.TempDir(), "",
		WithAllowPrivateNetwork(true),
		WithForwardRequestHeaders([]string{"Authorization"}))
	target := "/download?url=" + url.QueryEscape(upstream.URL+"/file") + "&filename=file"

	// 第一次请求：上游返回挑战
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, target, nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("WWW-Authenticate header is missing")
	}

	// 带上凭据重试：Authorization 被转发，上游放行
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.SetBasicAuth("user", "pass")
	rr = httptest.NewRecorder()
	dh.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Body.String(); got != "authorized" {
		t.Fatalf("body = %q, want %q", got, "authorized")
	}
}

// 跨源重定向不能把用户追加的透传请求头（可能含凭据）带到第三方主机。
func TestRedirectStripsCustomForwardedHeaders(t *testing.T) {
	received := make(chan string, 1)
	initial := make(chan string, 1)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("X-Api-Key")
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		initial <- r.Header.Get("X-Api-Key")
		http.Redirect(w, r, target.URL+"/file", http.StatusFound)
	}))
	defer redirector.Close()

	dh := NewDownloadHandler(t.TempDir(), "",
		WithAllowPrivateNetwork(true),
		WithForwardRequestHeaders([]string{"X-Api-Key"}))

	req := httptest.NewRequest(http.MethodGet,
		"/download?url="+url.QueryEscape(redirector.URL+"/start")+"&filename=file", nil)
	req.Header.Set("X-Api-Key", "secret-token")
	rr := httptest.NewRecorder()
	dh.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := <-initial; got != "secret-token" {
		t.Fatalf("initial request X-Api-Key = %q, want %q", got, "secret-token")
	}
	if got := <-received; got != "" {
		t.Fatalf("X-Api-Key leaked to redirect target: %q", got)
	}
}

func TestSanitizeFilename(t *testing.T) {
	if got := sanitizeFilename("a\x00b\nc\x7fd"); got != "abcd" {
		t.Fatalf("sanitizeFilename() = %q, want %q", got, "abcd")
	}
	if got := sanitizeFilename(`C:\dir\..\file.txt`); got != "file.txt" {
		t.Fatalf("sanitizeFilename() = %q, want %q", got, "file.txt")
	}
	if got := sanitizeFilename("/etc/passwd"); got != "passwd" {
		t.Fatalf("sanitizeFilename() = %q, want %q", got, "passwd")
	}
	if got := sanitizeFilename("  file.txt  "); got != "file.txt" {
		t.Fatalf("sanitizeFilename() = %q, want %q", got, "file.txt")
	}
	longName := strings.Repeat("a", maxFilenameRunes+10)
	if got := sanitizeFilename(longName); len([]rune(got)) != maxFilenameRunes {
		t.Fatalf("sanitizeFilename() length = %d, want %d", len([]rune(got)), maxFilenameRunes)
	}
}
