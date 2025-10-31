package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/junlongzzz/file-download-agent/common"
	"github.com/mssola/useragent"
)

type DownloadHandler struct {
	signKey string               // 参数校验签名key
	client  *http.Client         // 发起请求的http客户端
	dir     string               // 文件下载目录
	ua      *useragent.UserAgent // 解析user-agent的工具
}

type DownloadParams struct {
	Url      string `json:"url"`                // 下载链接
	Filename string `json:"filename,omitempty"` // 下载保存文件名
	Expire   string `json:"expire,omitempty"`   // 下载链接有效期 截止时间的时间戳，单位：秒
	Sign     string `json:"sign,omitempty"`     // 参数签名 omitempty:如果为空值时在json序列化时会被忽略输出
}

// NewDownloadHandler 初始化并赋默认值
func NewDownloadHandler(dir, signKey string) *DownloadHandler {
	return &DownloadHandler{
		signKey: signKey,
		client:  defaultHTTPClient(),
		dir:     dir,
		ua:      &useragent.UserAgent{},
	}
}

// 默认的请求发起http客户端
func defaultHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 设置最大重定向次数
			if len(via) >= 20 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// SetClient 设置HttpClient
func (dh *DownloadHandler) SetClient(client *http.Client) {
	if client != nil {
		dh.client = client
	}
}

// 文件下载处理函数，实现了 Handler 接口
func (dh *DownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// POST请求用于处理数据
		// 获取请求体参数
		body := &DownloadParams{}
		if err := json.NewDecoder(r.Body).Decode(body); err != nil {
			_ = dh.jsonResponse(w, http.StatusBadRequest, "Invalid request body", nil)
			return
		}
		defer r.Body.Close()

		if body.Url == "" {
			_ = dh.jsonResponse(w, http.StatusBadRequest, "Missing required parameter: url", nil)
			return
		}

		signKey := body.Sign
		// 通过置空签名密钥进行移除从而不进行传递
		body.Sign = ""
		needEncData, _ := json.Marshal(body)
		encrypt, err := common.Encrypt(signKey, needEncData)
		signKey = ""
		if err != nil {
			_ = dh.jsonResponse(w, http.StatusInternalServerError, "Failed to encrypt data", nil)
			return
		}

		// 返回响应
		_ = dh.jsonResponse(w, http.StatusOK, "success", base64.StdEncoding.EncodeToString(encrypt))
		return
	} else if r.Method != http.MethodGet {
		// GET请求就是下载
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	params := &DownloadParams{}
	// 加密参数
	enc := r.URL.Query().Get("enc")
	if enc != "" {
		encBytes, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			slog.Error(fmt.Sprintf("enc base64 decode error: %v", err))
			http.Error(w, "Invalid enc", http.StatusBadRequest)
			return
		}
		encDecrypt, err := common.Decrypt(dh.signKey, encBytes)
		if err != nil {
			slog.Error(fmt.Sprintf("enc decrypt error: %v", err))
			http.Error(w, "Invalid enc", http.StatusBadRequest)
			return
		}
		if err = json.Unmarshal(encDecrypt, &params); err != nil {
			slog.Error(fmt.Sprintf("enc json unmarshal error: %v", err))
			http.Error(w, "Invalid enc", http.StatusBadRequest)
			return
		}
	} else {
		params.Url = r.URL.Query().Get("url")
		params.Filename = r.URL.Query().Get("filename")
		params.Expire = r.URL.Query().Get("expire")
		params.Sign = r.URL.Query().Get("sign")
	}

	if params.Url == "" {
		// 缺少必须参数
		http.Error(w, "Missing required parameter: url", http.StatusBadRequest)
		return
	}

	if enc == "" && dh.signKey != "" {
		// 需要签名校验的参数，为空的参数不校验 sign = md5(filename + "|" + url + "|" + expire + "|" + <your_sign_key>)
		var needSignParams []string
		if params.Filename != "" {
			needSignParams = append(needSignParams, params.Filename)
		}
		needSignParams = append(needSignParams, params.Url)
		if params.Expire != "" {
			needSignParams = append(needSignParams, params.Expire)
		}
		needSignParams = append(needSignParams, dh.signKey)

		if strings.ToLower(params.Sign) != common.CalculateMD5(strings.Join(needSignParams, "|")) {
			// 数据签名不匹配，返回错误信息
			http.Error(w, "Invalid sign", http.StatusBadRequest)
			return
		}
	}

	parseUrl, err := url.Parse(params.Url)
	if err != nil {
		http.Error(w, "Failed to parse url", http.StatusBadRequest)
		return
	}

	// 校验url是否合法
	if parseUrl.Scheme != "http" && parseUrl.Scheme != "https" && parseUrl.Scheme != "file" {
		http.Error(w, "Invalid url", http.StatusBadRequest)
		return
	}

	if params.Filename == "" {
		// 如果没有指定下载文件名，直接从链接地址中获取
		if parseUrl.Path != "" {
			params.Filename = path.Base(parseUrl.Path)
		} else {
			params.Filename = parseUrl.Hostname()
		}
	}

	if params.Expire != "" {
		// 校验下载链接是否过期
		timestamp, err := strconv.ParseInt(params.Expire, 10, 64)
		if err != nil {
			http.Error(w, "Invalid expire parameter: must be a valid UNIX timestamp", http.StatusBadRequest)
			return
		}
		expireTime := time.Unix(timestamp, 0)
		currentTime := time.Now()
		if currentTime.After(expireTime) {
			http.Error(w, "Link has expired", http.StatusForbidden)
			return
		}
	}

	var written int64
	if parseUrl.Scheme == "file" {
		downPath, _ := url.QueryUnescape(parseUrl.RequestURI())
		written = dh.downloadFile(w, downPath, params.Filename)
	} else {
		written = dh.downloadUrl(w, r, params.Url, params.Filename)
	}
	if written >= 0 {
		// 解析user-agent
		dh.ua.Parse(r.Header.Get("User-Agent"))
		brwName, brwVersion := dh.ua.Browser()
		// 打印下载日志 输出时间、访问UA、文件名、下载地址、文件大小
		slog.Info(fmt.Sprintf("%s - %s | Size: %s | IP: %s | UA: %s/%s(%s)",
			params.Url, params.Filename,
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
	response, err := dh.client.Do(request)
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
	filePath := filepath.Join(dh.dir, filepath.Clean(downPath))
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

// 返回JSON格式的响应
func (dh *DownloadHandler) jsonResponse(w http.ResponseWriter, code int, msg string, data any) error {
	w.Header().Set("Content-Type", "application/json")
	response := map[string]any{
		"code": code,
		"msg":  msg,
		"data": data,
	}
	return json.NewEncoder(w).Encode(response)
}
