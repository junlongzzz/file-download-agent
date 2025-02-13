package main

import (
	"embed"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/junlongzzz/file-download-agent/common"
	"github.com/junlongzzz/file-download-agent/handler"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var (
	downloadHandler *handler.DownloadHandler
	webDavHandler   *handler.WebDavHandler
	staticHandler   *handler.StaticHandler

	//go:embed static/*
	static embed.FS
)

// 程序入口执行函数
func main() {
	versionInfo := fmt.Sprintf("File Download Agent v%s (%s %s/%s)", common.Version(), runtime.Version(), runtime.GOOS, runtime.GOARCH)

	// 从环境变量内读取运行参数
	host := os.Getenv("FDA_HOST")
	port, _ := strconv.Atoi(os.Getenv("FDA_PORT"))
	signKey := os.Getenv("FDA_SIGN_KEY")
	dir := os.Getenv("FDA_DIR")
	logLevel := os.Getenv("FDA_LOG_LEVEL")
	webDavDir := os.Getenv("FDA_WEBDAV_DIR")
	webDavUser := os.Getenv("FDA_WEBDAV_USER")
	webDavPass := os.Getenv("FDA_WEBDAV_PASS")
	certFile := os.Getenv("FDA_CERT_FILE")
	certKeyFile := os.Getenv("FDA_CERT_KEY_FILE")
	// 从运行参数中获取运行参数
	// 会覆盖环境变量的值，如果不存在默认就使用环境变量内的值
	flag.StringVar(&host, "host", host, "server host")
	flag.IntVar(&port, "port", port, "server port")
	flag.StringVar(&signKey, "sign-key", signKey, "server download sign key")
	flag.StringVar(&dir, "dir", dir, "download directory, default ./files")
	flag.StringVar(&webDavDir, "webdav-dir", webDavDir, "webdav root directory, default use <dir>")
	flag.StringVar(&webDavUser, "webdav-user", webDavUser, "webdav username, default anonymous")
	flag.StringVar(&webDavPass, "webdav-pass", webDavPass, "webdav password, default md5(sign_key)")
	flag.StringVar(&logLevel, "log-level", logLevel, "log level: debug, info, warn, error")
	flag.StringVar(&certFile, "cert-file", certFile, "cert file path")
	flag.StringVar(&certKeyFile, "cert-key-file", certKeyFile, "cert key file path")
	var version bool
	flag.BoolVar(&version, "version", false, "show version")
	// 解析命令行参数
	flag.Parse()

	if version {
		fmt.Println(versionInfo)
		os.Exit(0)
	}

	// 设置日志输出级别
	var slogLevel slog.Level
	switch strings.ToLower(logLevel) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	slog.SetLogLoggerLevel(slogLevel)

	slog.Info(versionInfo)

	if signKey != "" {
		slog.Info("Sign key has been set")
	}

	if dir == "" {
		// 默认下载目录为当前程序执行目录
		executable, err := os.Executable()
		if err == nil {
			dir = filepath.Join(filepath.Dir(executable), "files")
			// 判断文件夹是否存在，否则创建
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				// 文件夹不存在，创建
				if err := os.Mkdir(dir, os.ModePerm); err != nil {
					slog.Error(fmt.Sprintf("Create directory error: %v", err))
					os.Exit(1)
				}
			}
		} else {
			slog.Error(fmt.Sprintf("Get executable path error: %v", err))
			os.Exit(1)
		}
	}
	slog.Info(fmt.Sprintf("Download directory: %s", dir))

	if webDavDir == "" {
		// 未设置webdav目录，使用下载目录
		webDavDir = dir
	}
	slog.Info(fmt.Sprintf("WebDAV directory: %s", webDavDir))
	if webDavUser == "" {
		// 未设置webdav用户名，使用匿名用户
		webDavUser = "anonymous"
	}
	if webDavPass == "" && signKey != "" {
		// 未设置webdav密码，使用sign_key的md5值
		webDavPass = common.CalculateMD5(signKey)
	}

	// 初始化handler
	downloadHandler = handler.NewDownloadHandler(dir, signKey)
	webDavHandler = handler.NewWebDavHandler(webDavDir, webDavUser, webDavPass)
	staticHandler = handler.NewStaticHandler(static)

	// 启动服务器
	server(host, port, certFile, certKeyFile)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	signalReceived := <-signalChan
	slog.Info(fmt.Sprintf("Server stopped (signal: %v)", signalReceived))
	os.Exit(0)
}

// 启动HTTP服务器
func server(host string, port int, certFile, keyFile string) {
	if port <= 0 || port >= 65535 {
		// 不合法端口号，重置为默认端口
		port = 18080
	}

	// 创建路由器
	serveMux := http.NewServeMux()
	// 注册默认根路径路由
	serveMux.Handle("/", staticHandler)
	// 注册访问路由
	serveMux.Handle("/download", downloadHandler)
	serveMux.Handle("/webdav/", webDavHandler)

	go func() {
		// 启动HTTP服务器 异步
		// 创建服务器
		httpServer := &http.Server{
			Addr: fmt.Sprintf("%s:%d", host, port),
		}
		var err error
		if certFile != "" && keyFile != "" {
			// 支持 https 的服务器
			httpServer.Handler = serveMux
			slog.Info(fmt.Sprintf("Server is running on %s with HTTPS", httpServer.Addr))
			err = httpServer.ListenAndServeTLS(certFile, keyFile)
		} else {
			// 支持 h2c 的服务器，兼容 http/1.1
			httpServer.Handler = h2c.NewHandler(serveMux, &http2.Server{})
			slog.Info(fmt.Sprintf("Server is running on %s", httpServer.Addr))
			err = httpServer.ListenAndServe()
		}
		if err != nil {
			slog.Error(fmt.Sprintf("Server start error: %v", err))
			os.Exit(1)
		}
	}()
}
