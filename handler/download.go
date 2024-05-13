package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"file-download-agent/common"
)

type DownloadHandler struct {
	SignKey string // 参数校验签名key，首字母大写表示外部可调用
}

// 创建一个 HTTP 客户端
var client = &http.Client{
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

// Download 文件下载处理函数，首字母大写表示外部可调用
func (d *DownloadHandler) Download(w http.ResponseWriter, r *http.Request) {
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

	if d.SignKey != "" &&
		strings.ToLower(sign) != common.CalculateMD5(filename+"|"+urlStr+"|"+d.SignKey) {
		// 数据签名不匹配，返回错误信息
		http.Error(w, "Invalid sign", http.StatusBadRequest)
		return
	}

	if filename == "" {
		// 如果没有指定下载文件名，直接从链接地址中获取
		filename = path.Base(parseUrl.Path)
	}

	// 发起GET请求
	request, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create request: %v", err), http.StatusInternalServerError)
		return
	}
	// 设置请求头
	request.Header.Set("User-Agent", r.Header.Get("User-Agent"))
	// 发送 HTTP 请求
	response, err := client.Do(request)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send request: %v", err), http.StatusInternalServerError)
		return
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			// 处理关闭错误
			fmt.Println("Error closing response body:", err)
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

	// 打印下载日志 输出时间、访问UA、文件名、下载地址、文件大小
	fmt.Printf("%s | %s - %s | Size: %s | IP: %s | UA: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		filename,
		urlStr,
		common.FormatBytes(bytesCopied),
		common.GetRealIP(r),
		r.Header.Get("User-Agent"))
}
