package handler

import (
	"net/http"

	"golang.org/x/net/webdav"
)

type WebDavHandler struct {
	// webdav handler
	handler *webdav.Handler
	// basic 用户名 密码
	username, password string
}

// NewWebDavHandler 创建Handler
func NewWebDavHandler(dir, username, password string) *WebDavHandler {
	return &WebDavHandler{
		handler: &webdav.Handler{
			Prefix:     "/webdav",
			FileSystem: webdav.Dir(dir),
			LockSystem: webdav.NewMemLS(),
		},
		username: username,
		password: password,
	}
}

// SetBasicAuth 设置basic认证信息
func (wh *WebDavHandler) SetBasicAuth(username, password string) {
	wh.username = username
	wh.password = password
}

func (wh *WebDavHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if wh.username != "" && wh.password != "" {
		username, password, ok := r.BasicAuth()
		if !ok || username != wh.username || password != wh.password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	wh.handler.ServeHTTP(w, r)
}
