package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/junlongzzz/file-download-agent/common"
	"golang.org/x/net/webdav"
)

type WebDavHandler struct {
	// webdav handler
	handler *webdav.Handler
	// basic 用户名 密码
	username, password string
	// 认证失败限流器
	authFailures *authFailureLimiter
}

// NewWebDavHandler 创建Handler
func NewWebDavHandler(dir, username, password string) *WebDavHandler {
	return &WebDavHandler{
		handler: &webdav.Handler{
			Prefix:     "/webdav",
			FileSystem: webdav.Dir(dir),
			LockSystem: webdav.NewMemLS(),
		},
		username:     username,
		password:     password,
		authFailures: newAuthFailureLimiter(defaultMaxAuthFailures, defaultAuthFailureWindow),
	}
}

// SetAuthLimit 配置认证失败限流参数
func (wh *WebDavHandler) SetAuthLimit(maxFailures int, window time.Duration) {
	wh.authFailures = newAuthFailureLimiter(maxFailures, window)
}

// SetBasicAuth 设置basic认证信息
func (wh *WebDavHandler) SetBasicAuth(username, password string) {
	wh.username = username
	wh.password = password
}

func (wh *WebDavHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if wh.username != "" && wh.password != "" {
		username, password, ok := r.BasicAuth()
		if !ok {
			// 未携带凭据是 Basic Auth 的正常挑战流程，不计入失败次数
			challengeBasicAuth(w)
			return
		}
		// 先校验凭据再检查限流：Basic Auth 比较很廉价，正确凭据必须放行。
		// 否则共享出口 IP 上的合法用户会被他人的失败尝试锁死，而且在
		// blocked() 之前无法通过正确密码重置计数。两个比较都要执行，
		// 避免短路求值通过耗时泄露用户名是否正确。
		usernameOK := constantTimeEqual(username, wh.username)
		passwordOK := constantTimeEqual(password, wh.password)
		if usernameOK && passwordOK {
			wh.authFailures.reset(common.GetRealIP(r))
			wh.handler.ServeHTTP(w, r)
			return
		}

		client := common.GetRealIP(r)
		if retryAfter, blocked := wh.authFailures.blocked(client); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
			http.Error(w, "Too many failed attempts, please try again later", http.StatusTooManyRequests)
			return
		}
		wh.authFailures.fail(client)
		challengeBasicAuth(w)
		return
	}
	wh.handler.ServeHTTP(w, r)
}

func challengeBasicAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
