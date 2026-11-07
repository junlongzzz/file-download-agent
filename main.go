package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
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
	"time"

	"github.com/junlongzzz/file-download-agent/common"
	"github.com/junlongzzz/file-download-agent/handler"
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

	// 记录在日志级别初始化前发现的配置问题，稍后统一输出
	var configWarnings []string

	// 从环境变量内读取运行参数
	host := os.Getenv("FDA_HOST")
	port, _ := strconv.Atoi(os.Getenv("FDA_PORT"))
	signKey := os.Getenv("FDA_SIGN_KEY")
	dir := os.Getenv("FDA_DIR")
	logLevel := os.Getenv("FDA_LOG_LEVEL")
	webDavEnableEnv := os.Getenv("FDA_WEBDAV_ENABLE")
	// 默认启用webdav
	webDavEnable := true
	if webDavEnableEnv != "" {
		parsed, ok := parseBoolValue(webDavEnableEnv)
		if !ok {
			// 非法值不能静默变成 false，否则 WebDAV 会被意外关闭
			configWarnings = append(configWarnings,
				fmt.Sprintf("Ignoring invalid FDA_WEBDAV_ENABLE value %q (expected true/false, yes/no, or on/off)", webDavEnableEnv))
		} else {
			webDavEnable = parsed
		}
	}
	webDavDir := os.Getenv("FDA_WEBDAV_DIR")
	webDavUser := os.Getenv("FDA_WEBDAV_USER")
	webDavPass := os.Getenv("FDA_WEBDAV_PASS")
	certFile := os.Getenv("FDA_CERT_FILE")
	certKeyFile := os.Getenv("FDA_CERT_KEY_FILE")
	forwardRequestHeadersValue := os.Getenv("FDA_FORWARD_REQUEST_HEADERS")
	forwardResponseHeadersValue := os.Getenv("FDA_FORWARD_RESPONSE_HEADERS")
	allowPrivateNetworkEnv := os.Getenv("FDA_ALLOW_PRIVATE_NETWORK")
	// 默认阻止访问内网/回环地址，防止 SSRF
	allowPrivateNetwork := false
	if allowPrivateNetworkEnv != "" {
		parsed, ok := parseBoolValue(allowPrivateNetworkEnv)
		if !ok {
			configWarnings = append(configWarnings,
				fmt.Sprintf("Ignoring invalid FDA_ALLOW_PRIVATE_NETWORK value %q (expected true/false, yes/no, or on/off)", allowPrivateNetworkEnv))
		} else {
			allowPrivateNetwork = parsed
		}
	}
	authMaxFailures := 10
	if authMaxFailuresEnv := os.Getenv("FDA_AUTH_MAX_FAILURES"); authMaxFailuresEnv != "" {
		if parsed, err := strconv.Atoi(authMaxFailuresEnv); err == nil {
			authMaxFailures = parsed
		}
	}
	authFailureWindow := time.Minute
	if authFailureWindowEnv := os.Getenv("FDA_AUTH_FAILURE_WINDOW"); authFailureWindowEnv != "" {
		if parsed, err := time.ParseDuration(authFailureWindowEnv); err == nil {
			authFailureWindow = parsed
		}
	}
	// 从运行参数中获取运行参数
	// 会覆盖环境变量的值，如果不存在默认就使用环境变量内的值
	flag.StringVar(&host, "host", host, "server host (default 0.0.0.0)")
	flag.IntVar(&port, "port", port, "server port (default 18080)")
	flag.StringVar(&signKey, "sign-key", signKey, "server download sign key")
	flag.StringVar(&dir, "dir", dir, "download directory (default files next to the executable)")
	flag.BoolVar(&webDavEnable, "webdav-enable", webDavEnable, "enable webdav server or not")
	flag.StringVar(&webDavDir, "webdav-dir", webDavDir, "webdav root directory (default <dir>)")
	flag.StringVar(&webDavUser, "webdav-user", webDavUser, "webdav username (default anonymous)")
	flag.StringVar(&webDavPass, "webdav-pass", webDavPass, "webdav password (default <sign_key> or random)")
	flag.StringVar(&logLevel, "log-level", logLevel, "log level: debug, info, warn, error (default info)")
	flag.StringVar(&certFile, "cert-file", certFile, "cert file path")
	flag.StringVar(&certKeyFile, "cert-key-file", certKeyFile, "cert key file path")
	flag.StringVar(&forwardRequestHeadersValue, "forward-request-headers", forwardRequestHeadersValue, "comma-separated extra request headers to forward upstream, e.g. Cookie,Authorization (default none)")
	flag.StringVar(&forwardResponseHeadersValue, "forward-response-headers", forwardResponseHeadersValue, "comma-separated extra response headers to forward to the client, e.g. Set-Cookie (default none)")
	flag.BoolVar(&allowPrivateNetwork, "allow-private-network", allowPrivateNetwork, "allow accessing private, loopback and link-local addresses (default false)")
	flag.IntVar(&authMaxFailures, "auth-max-failures", authMaxFailures, "max auth failures per client per window (default 10)")
	flag.DurationVar(&authFailureWindow, "auth-failure-window", authFailureWindow, "auth failure rate limit window (default 1m)")
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

	for _, warning := range configWarnings {
		slog.Warn(warning)
	}

	slog.Info(versionInfo)

	if signKey != "" {
		slog.Info("Sign key has been set")
		if len(signKey) < 16 {
			slog.Warn("Sign key is shorter than 16 characters; use a long random value to resist online guessing")
		}
	}

	if authMaxFailures < 1 {
		slog.Warn("Auth max failures must be positive, using 10")
		authMaxFailures = 10
	}
	if authFailureWindow <= 0 {
		slog.Warn("Auth failure window must be positive, using 1m")
		authFailureWindow = time.Minute
	}
	slog.Info(fmt.Sprintf("Auth failure limit: %d per %s", authMaxFailures, authFailureWindow))

	if dir == "" {
		// 默认下载目录为当前程序执行目录
		executable, err := os.Executable()
		if err != nil {
			slog.Error(fmt.Sprintf("Get executable path error: %v", err))
			os.Exit(1)
		}
		dir = filepath.Join(filepath.Dir(executable), "files")
	}
	// 无论目录来自默认值还是显式参数，都确保它存在
	if err := os.MkdirAll(dir, 0o755); err != nil {
		slog.Error(fmt.Sprintf("Create directory error: %v", err))
		os.Exit(1)
	}
	slog.Info(fmt.Sprintf("Download directory: %s", dir))

	if webDavEnable {
		slog.Info("WebDAV is enabled")
		if webDavDir == "" {
			// 未设置webdav目录，使用下载目录
			webDavDir = dir
		}
		// 显式指定且不存在的 webdav 目录同样需要创建，否则 PROPFIND/PUT 会失败
		if err := os.MkdirAll(webDavDir, 0o755); err != nil {
			slog.Error(fmt.Sprintf("Create WebDAV directory error: %v", err))
			os.Exit(1)
		}
		slog.Info(fmt.Sprintf("WebDAV directory: %s", webDavDir))
		if webDavUser == "" {
			// 未设置webdav用户名，使用匿名用户
			webDavUser = "anonymous"
		}
		if webDavPass == "" {
			if signKey != "" {
				// 未设置webdav密码，使用signKey
				webDavPass = signKey
			} else {
				// 既没有 signKey 也没有密码时生成随机密码，避免匿名可写。
				// 密码必须让运维看到，不能受 -log-level 过滤，因此直接写 stderr。
				// 该密码每次重启都会变化，生产环境应显式设置 -webdav-pass 或 -sign-key。
				webDavPass = randomPassword()
				_, _ = fmt.Fprintf(os.Stderr,
					"WARN WebDAV password not set, generated random password: %s (changes on every restart; set -webdav-pass or -sign-key)\n",
					webDavPass)
			}
		}
		// 初始化 webdav handler
		webDavHandler = handler.NewWebDavHandler(webDavDir, webDavUser, webDavPass)
		webDavHandler.SetAuthLimit(authMaxFailures, authFailureWindow)
	} else {
		slog.Info("WebDAV is disabled")
		webDavHandler = nil
	}

	// 解析额外允许转发的请求头/响应头列表
	forwardRequestHeaders := parseHeaderList(forwardRequestHeadersValue)
	forwardResponseHeaders := parseHeaderList(forwardResponseHeadersValue)
	if len(forwardRequestHeaders) > 0 {
		slog.Info(fmt.Sprintf("Forwarding request headers: %s", strings.Join(forwardRequestHeaders, ", ")))
		if signKey == "" {
			slog.Warn("Request headers are forwarded without signKey; anyone who can reach /download can relay them to arbitrary hosts")
		}
	}
	if len(forwardResponseHeaders) > 0 {
		slog.Info(fmt.Sprintf("Forwarding response headers: %s", strings.Join(forwardResponseHeaders, ", ")))
	}
	if allowPrivateNetwork {
		slog.Warn("Private network access is allowed, SSRF protection is disabled")
	}

	// 初始化handler
	downloadHandler = handler.NewDownloadHandler(dir, signKey,
		handler.WithForwardRequestHeaders(forwardRequestHeaders),
		handler.WithForwardResponseHeaders(forwardResponseHeaders),
		handler.WithAllowPrivateNetwork(allowPrivateNetwork))
	downloadHandler.SetAuthLimit(authMaxFailures, authFailureWindow)
	staticHandler = handler.NewStaticHandler(static)

	// 启动服务器
	httpServer := server(host, port, certFile, certKeyFile)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	signalReceived := <-signalChan
	slog.Info(fmt.Sprintf("Server stopped (signal: %v)", signalReceived))

	// 优雅关闭，等待进行中的请求完成
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error(fmt.Sprintf("Server shutdown error: %v", err))
	}
	os.Exit(0)
}

// 启动HTTP服务器
func server(host string, port int, certFile, keyFile string) *http.Server {
	if port <= 0 || port > 65535 {
		// 不合法端口号，重置为默认端口
		port = 18080
	}

	// 创建路由器
	serveMux := http.NewServeMux()
	// 注册默认根路径路由
	serveMux.Handle("/", staticHandler)
	// 注册访问路由
	serveMux.Handle("/download", downloadHandler)
	if webDavHandler != nil {
		serveMux.Handle("/webdav/", webDavHandler)
	}

	// 支持 h2c 的服务器，兼容 http/1.1
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	httpServer := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", host, port),
		Handler:   serveMux,
		Protocols: protocols,
		// 防止慢速请求头攻击；不设置 WriteTimeout 以免截断大文件下载
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		// 启动HTTP服务器 异步
		var err error
		if certFile != "" && keyFile != "" {
			// 支持 https 的服务器
			slog.Info(fmt.Sprintf("Server is running on %s with HTTPS", httpServer.Addr))
			err = httpServer.ListenAndServeTLS(certFile, keyFile)
		} else {
			slog.Info(fmt.Sprintf("Server is running on %s", httpServer.Addr))
			err = httpServer.ListenAndServe()
		}
		// Shutdown 触发的关闭属于正常流程
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error(fmt.Sprintf("Server start error: %v", err))
			os.Exit(1)
		}
	}()
	return httpServer
}

// 解析布尔配置，兼容 true/false、yes/no、on/off 等常见写法
func parseBoolValue(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "yes", "y", "on", "enable", "enabled":
		return true, true
	case "0", "f", "false", "no", "n", "off", "disable", "disabled":
		return false, true
	default:
		return false, false
	}
}

// 解析逗号分隔的头名称列表，忽略空白项
func parseHeaderList(value string) []string {
	var headers []string
	for _, header := range strings.Split(value, ",") {
		if header = strings.TrimSpace(header); header != "" {
			headers = append(headers, header)
		}
	}
	return headers
}

// 生成随机密码，用于未配置 WebDAV 密码时的默认凭据
func randomPassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		slog.Error(fmt.Sprintf("Generate random password error: %v", err))
		os.Exit(1)
	}
	return hex.EncodeToString(b)
}
