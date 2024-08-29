package handler

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"file-download-agent/common"
	"github.com/mssola/useragent"
)

type DownloadHandler struct {
	SignKey string       // 参数校验签名key
	Client  *http.Client // 发起请求的http客户端
	Dir     string       // 文件下载目录

	ua *useragent.UserAgent // 解析user-agent的工具
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
	if parseUrl.Scheme != "http" && parseUrl.Scheme != "https" && parseUrl.Scheme != "file" {
		http.Error(w, "Invalid url", http.StatusBadRequest)
		return
	}

	if dh.SignKey != "" && strings.ToLower(sign) != common.CalculateMD5(filename+"|"+urlStr+"|"+dh.SignKey) {
		// 数据签名不匹配，返回错误信息
		http.Error(w, "Invalid sign", http.StatusBadRequest)
		return
	}

	if filename == "" {
		// 如果没有指定下载文件名，直接从链接地址中获取
		if parseUrl.Path != "" {
			filename = path.Base(parseUrl.Path)
		} else {
			filename = parseUrl.Hostname()
		}
	}

	var written int64
	if parseUrl.Scheme == "file" {
		downPath, _ := url.QueryUnescape(parseUrl.RequestURI())
		written = dh.downloadFile(w, downPath, filename)
	} else {
		written = dh.downloadUrl(w, r, urlStr, filename)
	}
	if written >= 0 {
		// 解析user-agent
		dh.ua.Parse(r.Header.Get("User-Agent"))
		brwName, brwVersion := dh.ua.Browser()
		// 打印下载日志 输出时间、访问UA、文件名、下载地址、文件大小
		slog.Info(fmt.Sprintf("%s - %s | Size: %s | IP: %s | UA: %s/%s(%s)",
			urlStr,
			filename,
			common.FormatBytes(written),
			common.GetRealIP(r),
			dh.ua.OS(), brwName, brwVersion))
	}
}

// 下载远程文件
func (dh *DownloadHandler) downloadUrl(w http.ResponseWriter, r *http.Request, downUrl string, filename string) int64 {
	// 发起GET请求
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, downUrl, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return -1
	}
	// 设置请求头
	request.Header.Set("User-Agent", r.Header.Get("User-Agent"))
	// 发送 HTTP 请求
	response, err := dh.Client.Do(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return -1
	}
	defer func(Body io.ReadCloser) {
		if err := Body.Close(); err != nil {
			slog.Error(fmt.Sprintf("Failed to close response body: %v", err))
		}
	}(response.Body)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// 请求下载链接状态码不为成功就不进行后续操作
		http.Error(w, fmt.Sprintf("Request failed: %s - %s", downUrl, response.Status), response.StatusCode)
		return -1
	}

	// 设置响应头
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	contentLength := response.Header.Get("Content-Length")
	if contentLength != "" {
		w.Header().Set("Content-Length", contentLength)
	}

	// 将响应体写入到ResponseWriter
	written, err := io.Copy(w, response.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Download error: %v", err), http.StatusInternalServerError)
		return -1
	}
	return written
}

// 下载本地文件
func (dh *DownloadHandler) downloadFile(w http.ResponseWriter, downPath string, filename string) int64 {
	if downPath == "" {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return -1
	}
	// 构造文件的完整路径，需要对传入path进行clean，防止路径穿越
	filePath := filepath.Join(dh.Dir, filepath.Clean(downPath))
	// 检查文件是否存在
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "File not found", http.StatusNotFound)
			return -1
		}
		http.Error(w, "Unable to retrieve file info", http.StatusInternalServerError)
		return -1
	}
	if fileInfo.IsDir() {
		http.Error(w, "Requested path is not a file", http.StatusBadRequest)
		return -1
	}

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "Unable to open file", http.StatusInternalServerError)
		return -1
	}
	defer file.Close()

	// 设置响应头
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))

	// 将文件内容写入响应
	written, err := io.Copy(w, file)
	if err != nil {
		http.Error(w, "Unable to send file", http.StatusInternalServerError)
		return -1
	}
	return written
}
