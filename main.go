package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"

	"file-download-agent/handler"
)

// 语义化的版本号 Semantic Versioning
var (
	versionX byte = 1
	versionY byte = 0
	versionZ byte = 1
)

// 声明下载处理器
var downloadHandler = handler.NewDownloadHandler()

// 程序入口执行函数
func main() {
	// 设置日志输出级别
	slog.SetLogLoggerLevel(slog.LevelInfo)

	slog.Info(fmt.Sprintf("File Download Agent %s (%s %s/%s)", version(), runtime.Version(), runtime.GOOS, runtime.GOARCH))

	// 从环境变量内读取运行参数
	port, _ := strconv.Atoi(os.Getenv("FDA_PORT"))
	signKey := os.Getenv("FDA_SIGN_KEY")
	// 从运行参数中获取运行参数
	// 会覆盖环境变量的值，如果不存在默认就使用环境变量内的值
	flag.IntVar(&port, "port", port, "server port")
	flag.StringVar(&signKey, "sign-key", signKey, "server download sign key")
	// 解析命令行参数
	flag.Parse()

	if signKey != "" {
		downloadHandler.SignKey = signKey
		slog.Info("Enable sign check")
	}

	// 启动服务器
	server(port)
}

// 启动HTTP服务器
func server(port int) {
	if port <= 0 || port >= 65535 {
		// 不合法端口号，重置为默认端口
		port = 18080
	}

	// 创建路由器
	serveMux := http.NewServeMux()
	// 注册默认根路径路由
	serveMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		desc := `Name: File Download Agent
Description: This is file download agent server written in golang.
Version: %s
Author: Junlong Zhang
Usage:
  Endpoint: /download
  Method: GET
  Parameters: url (required), filename (optional), sign (optional)
  Remarks: sign = MD5(filename + "|" + url + "|" + signKey)`
		_, _ = fmt.Fprintf(w, desc, version())
	})
	// 注册文件下载路由
	serveMux.Handle("/download", downloadHandler)

	// 启动HTTP服务器
	addr := fmt.Sprintf(":%d", port)
	slog.Info(fmt.Sprintf("Server is running on %s...", addr))
	err := http.ListenAndServe(addr, serveMux)
	if err != nil {
		slog.Error(fmt.Sprintf("Server error: %v", err))
		os.Exit(1)
	}
}

// 获取 x.y.z 文本格式版本号
func version() string {
	return fmt.Sprintf("%v.%v.%v", versionX, versionY, versionZ)
}
