package main

import (
	"embed"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"file-download-agent/common"
	"file-download-agent/handler"
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
	// 从运行参数中获取运行参数
	// 会覆盖环境变量的值，如果不存在默认就使用环境变量内的值
	flag.StringVar(&host, "host", host, "server host")
	flag.IntVar(&port, "port", port, "server port")
	flag.StringVar(&signKey, "sign-key", signKey, "server download sign key")
	flag.StringVar(&dir, "dir", dir, "download directory, default ./files")
	flag.StringVar(&logLevel, "log-level", logLevel, "log level: debug, info, warn, error")
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
		break
	case "info":
		slogLevel = slog.LevelInfo
		break
	case "warn":
		slogLevel = slog.LevelWarn
		break
	case "error":
		slogLevel = slog.LevelError
		break
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
		if err != nil {
			slog.Error(fmt.Sprintf("Get executable path error: %v", err))
			os.Exit(1)
		} else {
			dir = filepath.Join(filepath.Dir(executable), "files")
		}
	}
	// 判断文件夹是否存在，否则创建
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		slog.Info(fmt.Sprintf("Directory %s does not exist, creating...", dir))
		if err := os.MkdirAll(dir, 0755); err != nil {
			slog.Error(fmt.Sprintf("Create directory error: %v", err))
			os.Exit(1)
		}
	} else if !info.IsDir() {
		// 存在但是不为文件夹
		slog.Error(fmt.Sprintf("Path %s is not a directory", dir))
		os.Exit(1)
	}
	slog.Info(fmt.Sprintf("Download directory: %s", dir))

	// 初始化handler
	downloadHandler = handler.NewDownloadHandler(dir, signKey)
	webDavHandler = handler.NewWebDavHandler(dir, "anonymous", common.CalculateMD5(signKey))
	staticHandler = handler.NewStaticHandler(static)

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
	serveMux.Handle("/", staticHandler)
	// 注册访问路由
	serveMux.Handle("/download", downloadHandler)
	serveMux.Handle("/webdav/", webDavHandler)

	// 启动HTTP服务器
	addr := fmt.Sprintf("%s:%d", host, port)
	slog.Info(fmt.Sprintf("Server is running on %s", addr))
	if err := http.ListenAndServe(addr, serveMux); err != nil {
		slog.Error(fmt.Sprintf("Server start error: %v", err))
		os.Exit(1)
	}
}
