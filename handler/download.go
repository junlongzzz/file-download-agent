package handler

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"

	"file-download-agent/common"
	"github.com/mssola/useragent"
)

type DownloadHandler struct {
	SignKey string               // 参数校验签名key
	Client  *http.Client         // 发起请求的http客户端
	ua      *useragent.UserAgent // 解析user-agent的工具
}

// NewDownloadHandler 初始化并赋默认值
func NewDownloadHandler() *DownloadHandler {
	return &DownloadHandler{
		SignKey: "",
		Client:  defaultHTTPClient(),
		ua:      &useragent.UserAgent{},
	}
}

// 默认的请求发起http客户端
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment, // 从环境变量中读取代理设置
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 设置最大重定向次数
			if len(via) >= 20 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// 文件下载处理函数，实现了 Handler 接口
func (dh *DownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 只接受get方式请求
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	urlStr := r.URL.Query().Get("url")
	filename := r.URL.Query().Get("filename")
	sign := r.URL.Query().Get("sign")

	if urlStr == "" {
		// 缺少必须参数
		http.Error(w, "Missing required parameter: url", http.StatusBadRequest)
		return
	}

	parseUrl, err := url.Parse(urlStr)
	if err != nil {
		http.Error(w, "Failed to parse url", http.StatusBadRequest)
		return
	}
	// 校验url是否合法
	if parseUrl.Scheme != "http" && parseUrl.Scheme != "https" {
		http.Error(w, "Invalid url", http.StatusBadRequest)
		return
	}

	if dh.SignKey != "" &&
		strings.ToLower(sign) != common.CalculateMD5(filename+"|"+urlStr+"|"+dh.SignKey) {
		// 数据签名不匹配，返回错误信息
		http.Error(w, "Invalid sign", http.StatusBadRequest)
		return
	}

	if filename == "" {
		// 如果没有指定下载文件名，直接从链接地址中获取
		filename = path.Base(parseUrl.Path)
	}

	// 发起GET请求
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, urlStr, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}
	// 设置请求头
	request.Header.Set("User-Agent", r.Header.Get("User-Agent"))
	// 发送 HTTP 请求
	response, err := dh.Client.Do(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			slog.Error(fmt.Sprintf("Failed to close response body: %v", err))
		}
	}(response.Body)

	if response.StatusCode != 200 {
		// 请求下载链接状态码不为成功就不进行后续操作
		http.Error(w, fmt.Sprintf("Request failed: %s - %s", urlStr, response.Status), response.StatusCode)
		return
	}

	// 设置响应头
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", url.QueryEscape(filename)))
	w.Header().Set("Content-Type", "application/octet-stream")
	// 获取文件大小
	contentLength := response.Header.Get("Content-Length")
	if contentLength != "" {
		w.Header().Set("Content-Length", contentLength)
	}

	// 将响应体写入到ResponseWriter
	bytesCopied, err := io.Copy(w, response.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Download error: %v", err), http.StatusInternalServerError)
		return
	}

	// 解析user-agent
	dh.ua.Parse(r.Header.Get("User-Agent"))
	brwName, brwVersion := dh.ua.Browser()
	// 打印下载日志 输出时间、访问UA、文件名、下载地址、文件大小
	slog.Info(fmt.Sprintf("%s - %s | Size: %s | IP: %s | UA: %s/%s(%s)",
		urlStr,
		filename,
		common.FormatBytes(bytesCopied),
		common.GetRealIP(r),
		dh.ua.OS(), brwName, brwVersion))
}
