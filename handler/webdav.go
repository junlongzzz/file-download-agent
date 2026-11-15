package handler

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/junlongzzz/file-download-agent/common"
	"golang.org/x/net/webdav"
)

type WebDavHandler struct {
	// webdav handler
	handler *webdav.Handler
	// 路径凭据认证使用的 handler，凭据不可用时为 nil
	pathHandler *webdav.Handler
	// 路径凭据：base64url(username:password)，与 Basic 头中的凭据内容一致
	pathCredential string
	// basic 用户名 密码
	username, password string
	// 认证失败限流器
	authFailures *authFailureLimiter
}

// NewWebDavHandler 创建Handler
func NewWebDavHandler(dir, username, password string) *WebDavHandler {
	wh := &WebDavHandler{
		handler: &webdav.Handler{
			Prefix:     "/webdav",
			FileSystem: webdav.Dir(dir),
			LockSystem: webdav.NewMemLS(),
		},
		authFailures: newAuthFailureLimiter(defaultMaxAuthFailures, defaultAuthFailureWindow),
	}
	wh.SetBasicAuth(username, password)
	return wh
}

// SetAuthLimit 配置认证失败限流参数
func (wh *WebDavHandler) SetAuthLimit(maxFailures int, window time.Duration) {
	wh.authFailures = newAuthFailureLimiter(maxFailures, window)
}

// SetBasicAuth 设置basic认证信息，并同步路径凭据认证入口。
// /webdav/<base64url(username:password)>/ 与 Basic 认证等价，供只能
// 填写 URL、无法发送认证头的客户端使用。路径段使用 Basic 头中的凭据
// 内容（base64），不额外引入 token 或配置项；凭据不匹配时仍回落到
// Basic 流程。注意 base64 是编码而非加密，能读到 URL 的人都能还原凭据。
func (wh *WebDavHandler) SetBasicAuth(username, password string) {
	wh.username = username
	wh.password = password
	wh.pathHandler = nil
	wh.pathCredential = ""
	if username == "" || password == "" {
		return
	}
	// 标准 base64 可能包含 "/"，会破坏 URL 路径段（也会被 ServeMux 清理），
	// 因此使用 URL 安全的 base64（- 和 _，无填充）。其余字符与 Basic 头一致。
	credential := base64.RawURLEncoding.EncodeToString([]byte(username + ":" + password))
	wh.pathCredential = credential
	// 只替换 Prefix，并共享 FileSystem/LockSystem：stripPrefix 会剥掉整个
	// 前缀，两个 handler 内部看到的路径完全一致，文件锁不会因入口不同而分裂。
	// PROPFIND 的 href 由 path.Join(h.Prefix, reqPath) 生成，因此响应中的
	// 子资源地址会自动带上路径凭据，挂载型客户端后续请求仍能通过认证。
	wh.pathHandler = &webdav.Handler{
		Prefix:     "/webdav/" + credential,
		FileSystem: wh.handler.FileSystem,
		LockSystem: wh.handler.LockSystem,
	}
}

func (wh *WebDavHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 路径凭据认证优先于 Basic：部分客户端会同时根据 URL 中的 userinfo
	// 生成 Basic 头，若先走 Basic 分支，/webdav/<base64url>/... 会被当成
	// 真实目录而返回 404。凭据不匹配时仍回落到下面的 Basic 流程。
	if wh.pathHandler != nil {
		if credential, ok := webdavPathCredential(r.URL.Path); ok && constantTimeEqual(credential, wh.pathCredential) {
			wh.authFailures.reset(common.GetRealIP(r))
			wh.pathHandler.ServeHTTP(w, r)
			return
		}
	}
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

// PathAuthEnabled 报告是否提供 URL 路径凭据认证。
func (wh *WebDavHandler) PathAuthEnabled() bool {
	return wh.pathHandler != nil
}

// webdavPathCredential 返回 /webdav/ 之后的第一段路径，即 base64url(username:password)。
// 路由只注册了 /webdav/，正常请求都带有该前缀；没有该前缀时返回 false。
func webdavPathCredential(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/webdav/")
	if !ok {
		return "", false
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}
