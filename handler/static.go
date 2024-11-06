package handler

import (
	"embed"
	"net/http"
	"strings"
)

type StaticHandler struct {
	// 文件服务器
	fileServer http.Handler
}

func NewStaticHandler(fs embed.FS) *StaticHandler {
	return &StaticHandler{
		fileServer: http.FileServerFS(fs),
	}
}

func (sh *StaticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 添加 /static 目录路径
	path := r.URL.Path
	if !strings.HasPrefix(path, "/static") {
		r.URL.Path = "/static" + path
	}
	sh.fileServer.ServeHTTP(w, r)
}
