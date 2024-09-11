package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"file-download-agent/handler"
)

// 语义化的版本号 Semantic Versioning
const (
	versionX byte = 1
	versionY byte = 2
	versionZ byte = 0
)

var (
	downloadHandler *handler.DownloadHandler
	webDavHandler   *handler.WebDavHandler
)

// 程序描述信息
const description = `Name: File Download Agent
Description: File download agent server written in golang.
Version: %s
Author: Junlong Zhang <junlong.plus>
Usage:
  - Endpoint: /download
    Method: GET
    Parameters:
      - url (required): Supported url schemes: http, https, file (NOTE: relative path e.g. file:///path/to/file.txt)
      - filename (optional): Saved file name
      - expire (optional): Link expiration timestamp, seconds
      - sign (optional): Parameter signature if <your_sign_key> is not empty
    Remarks:
      - sign = MD5(filename + "|" + url + "|" + expire + "|" + <your_sign_key>) (NOTE: Must exclude empty parameters and DO NOT url-encode)

  - Endpoint: /webdav
    Method: *
    Basic-Auth:
      - username: anonymous
      - password: MD5(<your_sign_key>)
    Remarks: Basic Auth is only valid if <your_sign_key> is not empty`

// 程序入口执行函数
func main() {
	// 设置日志输出级别
	slog.SetLogLoggerLevel(slog.LevelInfo)

	slog.Info(fmt.Sprintf("File Download Agent %s (%s %s/%s)", version(), runtime.Version(), runtime.GOOS, runtime.GOARCH))

	// 从环境变量内读取运行参数
	host := os.Getenv("FDA_HOST")
	port, _ := strconv.Atoi(os.Getenv("FDA_PORT"))
	signKey := os.Getenv("FDA_SIGN_KEY")
	dir := os.Getenv("FDA_DIR")
	// 从运行参数中获取运行参数
	// 会覆盖环境变量的值，如果不存在默认就使用环境变量内的值
	flag.StringVar(&host, "host", host, "server host")
	flag.IntVar(&port, "port", port, "server port")
	flag.StringVar(&signKey, "sign-key", signKey, "server download sign key")
	flag.StringVar(&dir, "dir", dir, "download directory, default ./files")
	// 解析命令行参数
	flag.Parse()

	if signKey != "" {
		slog.Info("Sign key has been set")
	}

	if dir == "" {
		// 默认下载目录为当前程序执行目录
		executable, err := os.Executable()
		if err != nil {
			slog.Error(fmt.Sprintf("Get executable path error: %v", err))
			os.Exit(1)
		} else {
			dir = filepath.Join(filepath.Dir(executable), "files")
		}
	}
	// 判断文件夹是否存在，否则创建
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			slog.Error(fmt.Sprintf("Create directory error: %v", err))
			os.Exit(1)
		}
	}
	slog.Info(fmt.Sprintf("Download directory: %s", dir))

	// 初始化handler
	downloadHandler = handler.NewDownloadHandler(dir)
	downloadHandler.SignKey = signKey
	webDavHandler = handler.NewWebDavHandler(dir)
	webDavHandler.SetBasicAuth("anonymous", signKey)

	// 启动服务器
	server(host, port)
}

// 启动HTTP服务器
func server(host string, port int) {
	if port <= 0 || port >= 65535 {
		// 不合法端口号，重置为默认端口
		port = 18080
	}

	// 创建路由器
	serveMux := http.NewServeMux()
	// 注册默认根路径路由
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, description, version())
	})
	// 注册访问路由
	serveMux.Handle("/download", downloadHandler)
	serveMux.Handle("/webdav/", webDavHandler)

	// 启动HTTP服务器
	addr := fmt.Sprintf("%s:%d", host, port)
	slog.Info(fmt.Sprintf("Server is running on http://%s", addr))
	if err := http.ListenAndServe(addr, serveMux); err != nil {
		slog.Error(fmt.Sprintf("Server error: %v", err))
		os.Exit(1)
	}
}

// 获取 x.y.z 文本格式版本号
func version() string {
	return fmt.Sprintf("%v.%v.%v", versionX, versionY, versionZ)
}
