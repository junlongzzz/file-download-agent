package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/junlongzzz/file-download-agent/common"
)

// POST 请求体的大小上限，避免超大 JSON 占用内存
const maxPostBodySize = 1 << 20

// 加密链接 enc 参数的长度上限，避免超大输入在解密前占用内存。
// 32 KiB 足以容纳常见的长签名 URL，同时远小于 POST 的 1 MiB 上限。
const maxEncodedEncLen = 32 << 10

// 文件名长度上限，避免异常响应头或参数生成过长的 Content-Disposition
const maxFilenameRunes = 255

type DownloadHandler struct {
	signKey             string              // 参数校验签名key
	client              *http.Client        // 发起请求的http客户端
	dir                 string              // 文件下载目录
	forwardReqHeaders   map[string]bool     // 允许透传的请求头白名单
	forwardRespHeaders  map[string]bool     // 允许透传的响应头白名单
	allowPrivateNetwork bool                // 是否允许访问内网/回环地址（关闭 SSRF 防护）
	authFailures        *authFailureLimiter // signKey 猜测失败限流器（POST 密钥校验、明文签名）
	encFailures         *authFailureLimiter // 加密链接解密失败限流器，与 signKey 限流相互独立
}

type DownloadParams struct {
	Url      string `json:"url"`                // 下载链接
	Filename string `json:"filename,omitempty"` // 下载保存文件名
	Expire   string `json:"expire,omitempty"`   // 下载链接有效期 截止时间的时间戳，单位：秒
	Sign     string `json:"sign,omitempty"`     // GET 为参数签名，POST 为客户端提供的 signKey omitempty:如果为空值时在json序列化时会被忽略输出
}

// DownloadOption 用于在构造 DownloadHandler 时覆盖默认行为
type DownloadOption func(*DownloadHandler)

// WithForwardRequestHeaders 在默认白名单之外，额外指定转发到上游的请求头，名称不区分大小写。
// 上游地址由请求参数决定，转发认证类请求头前请确保 /download 已启用签名保护。
func WithForwardRequestHeaders(headers []string) DownloadOption {
	return func(dh *DownloadHandler) {
		addHeaderNames(dh.forwardReqHeaders, headers)
	}
}

// WithForwardResponseHeaders 在默认白名单之外，额外指定回传给客户端的响应头，名称不区分大小写。
func WithForwardResponseHeaders(headers []string) DownloadOption {
	return func(dh *DownloadHandler) {
		addHeaderNames(dh.forwardRespHeaders, headers)
	}
}

// 将头名称规范化后加入白名单
func addHeaderNames(target map[string]bool, headers []string) {
	for _, header := range headers {
		if header = http.CanonicalHeaderKey(strings.TrimSpace(header)); header != "" {
			target[header] = true
		}
	}
}

// WithAllowPrivateNetwork 允许访问内网、回环、链路本地等地址，即关闭 SSRF 防护
func WithAllowPrivateNetwork(enabled bool) DownloadOption {
	return func(dh *DownloadHandler) {
		dh.allowPrivateNetwork = enabled
	}
}

// builtinForwardReqHeaders 是内置转发的请求头白名单。
// 内置头与用户通过 -forward-request-headers 追加的头需要区分：
// 跨源重定向时只移除用户追加的头，内置头不含凭据，可以继续转发。
var builtinForwardReqHeaders = map[string]bool{
	"Accept-Encoding":     true, // 与响应 Content-Encoding 配套
	"Range":               true, // 支持断点续传
	"If-Range":            true,
	"If-Match":            true, // 条件请求，客户端明确要求校验资源版本
	"If-Unmodified-Since": true,
	"If-None-Match":       true,
	"If-Modified-Since":   true,
	"User-Agent":          true,
}

// copyHeaderSet 复制白名单，避免多个 handler 共享同一个可变 map
func copyHeaderSet(src map[string]bool) map[string]bool {
	dst := make(map[string]bool, len(src))
	for name, enabled := range src {
		dst[name] = enabled
	}
	return dst
}

// NewDownloadHandler 初始化并赋默认值
func NewDownloadHandler(dir, signKey string, opts ...DownloadOption) *DownloadHandler {
	dh := &DownloadHandler{
		signKey:      signKey,
		dir:          dir,
		authFailures: newAuthFailureLimiter(defaultMaxAuthFailures, defaultAuthFailureWindow),
		encFailures:  newAuthFailureLimiter(defaultMaxAuthFailures, defaultAuthFailureWindow),
		// 内置白名单只包含下载功能必需的头，其余（Referer、Origin、Accept、
		// Accept-Language、Cache-Control 等）通过 WithForwardRequestHeaders 配置。
		forwardReqHeaders: copyHeaderSet(builtinForwardReqHeaders),
		// 同样只内置下载必需的头；Content-Disposition 由本服务生成（未指定
		// 文件名时读取上游 filename），Date 由 http.Server 自动添加，均无需
		// 转发。Set-Cookie 等通过 WithForwardResponseHeaders 配置。
		forwardRespHeaders: map[string]bool{
			"Content-Type":     true,
			"Content-Length":   true,
			"Content-Range":    true, // 断点续传支持
			"Content-Encoding": true, // 与请求 Accept-Encoding 配套
			"Accept-Ranges":    true,
			"Last-Modified":    true,
			"Etag":             true, // Go 的规范形式（CanonicalHeaderKey("ETag")）
			"Vary":             true, // 与 Accept-Encoding 配套，保证缓存变体正确
		},
	}
	for _, opt := range opts {
		opt(dh)
	}
	// 需要先应用选项（尤其是 allowPrivateNetwork）再创建客户端
	dh.client = defaultHTTPClient(dh)
	return dh
}

// 默认的请求发起http客户端
func defaultHTTPClient(dh *DownloadHandler) *http.Client {
	// 克隆默认 Transport，避免修改全局配置
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// 提高同一源站的空闲连接数，避免并发下载时频繁建连
	transport.MaxIdleConnsPerHost = 32
	// 不设置 ResponseHeaderTimeout：按需生成文件的上游可能需要较长时间才返回
	// 响应头，硬编码超时会截断原本可用的下载；连接由请求上下文控制取消。
	if !dh.allowPrivateNetwork {
		if hasProxyEnv() {
			// 使用代理时拨号目标是代理本身，无法在拨号层区分目标地址，
			// 由请求前的 DNS 检查负责拦截
			slog.Warn("HTTP proxy is configured, SSRF protection relies on pre-request DNS checks")
		} else {
			// 在拨号层再次校验实际连接 IP，防止 DNS rebinding 绕过请求前检查
			transport.DialContext = newRestrictedDialer().DialContext
		}
	}
	return &http.Client{
		Transport: transport,
		// 不设置 Client.Timeout：大文件下载耗时不受限制，由请求上下文控制取消
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 设置最大重定向次数
			if len(via) >= 20 {
				return fmt.Errorf("too many redirects")
			}
			// 每一跳都要重新校验，防止重定向到内网地址
			if !dh.allowPrivateNetwork {
				if err := checkHostIP(req.Context(), req.URL.Hostname()); err != nil {
					return err
				}
			}
			// net/http 会把原请求头复制到重定向请求，只跳过 Authorization/Cookie
			// 等敏感头。用户追加的透传头（如 X-Api-Key）会被带到第三方主机，
			// 因此跨源重定向时移除它们；内置头不含凭据，可以保留。
			if len(via) > 0 && !sameOrigin(req.URL, via[0].URL) {
				for header := range dh.forwardReqHeaders {
					if !builtinForwardReqHeaders[header] {
						req.Header.Del(header)
					}
				}
			}
			return nil
		},
	}
}

// sameOrigin 判断两个 URL 是否同源（协议和主机都相同）
func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// SetClient 设置HttpClient
func (dh *DownloadHandler) SetClient(client *http.Client) {
	if client != nil {
		dh.client = client
	}
}

// SetAuthLimit 配置认证失败限流参数
func (dh *DownloadHandler) SetAuthLimit(maxFailures int, window time.Duration) {
	dh.authFailures = newAuthFailureLimiter(maxFailures, window)
	dh.encFailures = newAuthFailureLimiter(maxFailures, window)
}

// 文件下载处理函数，实现了 Handler 接口
func (dh *DownloadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// POST请求用于处理数据
		// 限制请求体大小并在读取前注册关闭
		r.Body = http.MaxBytesReader(w, r.Body, maxPostBodySize)
		defer func() {
			_ = r.Body.Close()
		}()
		// 获取请求体参数
		body := &DownloadParams{}
		if err := json.NewDecoder(r.Body).Decode(body); err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				_ = dh.jsonResponse(w, http.StatusRequestEntityTooLarge, "Request body too large", nil)
				return
			}
			_ = dh.jsonResponse(w, http.StatusBadRequest, "Invalid request body", nil)
			return
		}

		if body.Url == "" {
			_ = dh.jsonResponse(w, http.StatusBadRequest, "Missing required parameter: url", nil)
			return
		}

		// GET 解密始终使用服务器 signKey，因此 POST 传入的密码必须与之一致，
		// 否则生成的链接必然无法解密。这里必须校验，否则任何人都能借服务器
		// 生成合法的加密链接，signKey 的访问保护就失效了。
		if dh.signKey != "" {
			client := common.GetRealIP(r)
			if retryAfter, blocked := dh.authFailures.blocked(client); blocked {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
				_ = dh.jsonResponse(w, http.StatusTooManyRequests,
					"Too many failed attempts, please try again later", nil)
				return
			}
			if !constantTimeEqual(body.Sign, dh.signKey) {
				dh.authFailures.fail(client)
				_ = dh.jsonResponse(w, http.StatusForbidden, "Invalid sign key", nil)
				return
			}
			dh.authFailures.reset(client)
		}

		// GET 解密始终使用服务器 signKey，因此加密也必须使用服务器 key；
		// 未配置 signKey 时客户端传入的 sign 无法参与解密，直接忽略。
		encryptKey := dh.signKey
		// 通过置空签名密钥进行移除从而不进行传递
		body.Sign = ""
		// 清理文件名，避免生成超出 GET 长度限制或包含控制字符的链接
		body.Filename = sanitizeFilename(body.Filename)
		needEncData, _ := json.Marshal(body)
		// 先粗略检查明文长度，避免为明显超长的参数运行昂贵的 KDF；
		// 加密后的精确长度检查在下方。
		if base64.RawURLEncoding.EncodedLen(len(needEncData)) > maxEncodedEncLen {
			_ = dh.jsonResponse(w, http.StatusBadRequest, "Generated link is too long", nil)
			return
		}
		encrypt, err := common.Encrypt(encryptKey, needEncData)
		encryptKey = ""
		if err != nil {
			_ = dh.jsonResponse(w, http.StatusInternalServerError, "Failed to encrypt data", nil)
			return
		}

		// 与 GET 的 enc 长度限制保持一致，避免生成无法使用的链接
		link := base64.RawURLEncoding.EncodeToString(encrypt)
		if len(link) > maxEncodedEncLen {
			_ = dh.jsonResponse(w, http.StatusBadRequest, "Generated link is too long", nil)
			return
		}
		// 返回响应
		_ = dh.jsonResponse(w, http.StatusOK, "success", link)
		return
	} else if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// GET 请求就是下载，HEAD 用于探测文件信息
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	params := &DownloadParams{}
	// 加密参数
	enc := r.URL.Query().Get("enc")
	if enc != "" {
		// 解密失败使用独立的限流器：加密链接可以公开分享，成功解密只说明
		// 持有链接，并不证明持有 signKey；与签名校验分开还能避免签名失败
		// 把合法加密下载一起锁死。
		params = dh.decodeEnc(w, enc, common.GetRealIP(r))
		if params == nil {
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
		client := common.GetRealIP(r)
		if retryAfter, blocked := dh.authFailures.blocked(client); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
			http.Error(w, "Too many failed attempts, please try again later", http.StatusTooManyRequests)
			return
		}

		// 签名输入用 "|" 拼接，参数中若包含 "|" 会产生分隔歧义：
		// 例如把 expire 拼到 url 末尾并省略 expire，签名输入仍然相同，
		// 从而绕过过期校验。直接拒绝这类参数。
		if strings.Contains(params.Filename, "|") ||
			strings.Contains(params.Url, "|") ||
			strings.Contains(params.Expire, "|") {
			http.Error(w, "Invalid parameter: '|' is not allowed in signed URLs", http.StatusBadRequest)
			return
		}

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

		expectedSign := common.CalculateMD5(strings.Join(needSignParams, "|"))
		// 常量时间比较，避免通过响应耗时推断签名
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(params.Sign)), []byte(expectedSign)) != 1 {
			// 数据签名不匹配，返回错误信息
			dh.authFailures.fail(client)
			http.Error(w, "Invalid sign", http.StatusBadRequest)
			return
		}
		// 校验成功不重置计数：签名链接可以转手分享，持有链接不代表持有 signKey，
		// 否则攻击者可用任意有效（甚至已过期）链接重置失败计数后继续爆破。
	}

	// 签名校验使用原始参数，校验通过后再清理文件名中的控制字符并限制长度，
	// 避免影响签名语义；加密链接同样在解密后统一处理。
	params.Filename = sanitizeFilename(params.Filename)

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

	if parseUrl.Scheme == "file" && params.Filename == "" {
		// 本地文件没有指定文件名时，直接从路径中获取；远程文件优先使用上游的 Content-Disposition
		params.Filename = sanitizeFilename(defaultFilename(parseUrl))
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
		// 使用 url.Parse 已解码的 Path，避免二次解码改变路径
		written = dh.downloadFile(w, r, parseUrl.Path, params.Filename)
	} else {
		written = dh.downloadUrl(w, r, params.Url, &params.Filename)
	}
	if written >= 0 {
		// 打印下载日志 输出时间、访问UA、文件名、下载地址、文件大小
		slog.Info(fmt.Sprintf("%s - %s | Size: %s | IP: %s | UA: %s",
			params.Url, params.Filename,
			common.FormatBytes(written),
			common.GetRealIP(r),
			r.Header.Get("User-Agent")))
	}
}

// decodeEnc 解密并解析 enc 参数。失败时已经写入错误响应，返回 nil 表示调用方
// 应直接返回。解密期间占用限流器的一个并发名额，解析完成立即释放，
// 不覆盖后续的文件传输时间。
func (dh *DownloadHandler) decodeEnc(w http.ResponseWriter, enc, client string) *DownloadParams {
	if !dh.encFailures.beginAttempt(client) {
		retryAfter, blocked := dh.encFailures.blocked(client)
		seconds := 1
		if blocked {
			seconds = retryAfterSeconds(retryAfter)
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		http.Error(w, "Too many failed or concurrent attempts, please try again later", http.StatusTooManyRequests)
		return nil
	}

	// 解密结束后立即释放并发名额并记录结果；成功不重置历史失败计数。
	failed := true
	defer func() {
		dh.encFailures.finishAttempt(client, failed)
	}()

	invalidEnc := func(err error) {
		slog.Error(fmt.Sprintf("enc decode error: %v", err))
		http.Error(w, "Invalid enc", http.StatusBadRequest)
	}
	if len(enc) > maxEncodedEncLen {
		invalidEnc(fmt.Errorf("enc too long: %d bytes", len(enc)))
		return nil
	}
	encBytes, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		invalidEnc(err)
		return nil
	}
	encDecrypt, err := common.Decrypt(dh.signKey, encBytes)
	if err != nil {
		invalidEnc(err)
		return nil
	}
	params := &DownloadParams{}
	if err = json.Unmarshal(encDecrypt, params); err != nil {
		invalidEnc(err)
		return nil
	}
	failed = false
	return params
}

// 下载远程文件
func (dh *DownloadHandler) downloadUrl(w http.ResponseWriter, r *http.Request, downUrl string, filename *string) int64 {
	// HEAD 请求用 HEAD 探测上游，避免下载整个文件
	method := http.MethodGet
	if r.Method == http.MethodHead {
		method = http.MethodHead
	}
	request, err := http.NewRequestWithContext(r.Context(), method, downUrl, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		slog.Error(fmt.Sprintf("Create request error: %v", err))
		return -1
	}
	// 请求前解析并校验目标地址，阻止访问内网、回环、链路本地等地址（SSRF）
	if !dh.allowPrivateNetwork {
		if err := checkHostIP(r.Context(), request.URL.Hostname()); err != nil {
			if errors.Is(err, errPrivateNetwork) {
				http.Error(w, "Request to a private or reserved network is not allowed", http.StatusForbidden)
			} else {
				http.Error(w, "Failed to resolve target host", http.StatusBadGateway)
			}
			slog.Error(fmt.Sprintf("Check target host error: %s - %v", downUrl, err))
			return -1
		}
	}
	// 透传请求头给目标地址
	for header, values := range r.Header {
		if dh.forwardReqHeaders[header] {
			for _, value := range values {
				request.Header.Add(header, value)
			}
		}
	}
	// 发送 HTTP 请求
	response, err := dh.client.Do(request)
	if err != nil {
		// 拨号层或重定向检查发现内网地址时同样返回 403
		if errors.Is(err, errPrivateNetwork) {
			http.Error(w, "Request to a private or reserved network is not allowed", http.StatusForbidden)
		} else {
			http.Error(w, "Failed to send request", http.StatusBadGateway)
		}
		slog.Error(fmt.Sprintf("Send request error: %s - %v", downUrl, err))
		return -1
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	// 304 是缓存校验的正常结果，直接透传，不能当作错误处理。
	// 响应没有 body，但 ETag、Last-Modified、Cache-Control 等缓存头必须回传。
	if response.StatusCode == http.StatusNotModified {
		dh.copyForwardResponseHeaders(w, response.Header, false)
		w.WriteHeader(http.StatusNotModified)
		return 0
	}

	// 状态码不为成功时直接返回错误。
	// 必须在透传响应头之前判断，否则上游的 Content-Encoding 等头会让 http.Error
	// 写入的明文错误内容被客户端当作压缩数据解码。
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// 416 需要回传 Content-Range，客户端据此得知资源的实际总长度
		if response.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			if value := response.Header.Get("Content-Range"); value != "" {
				w.Header().Set("Content-Range", value)
			}
		}
		// 401 的认证挑战只有在 Authorization 会被转发时才有意义：否则浏览器
		// 按挑战重试时携带的凭据会被丢弃，上游再次 401，形成认证循环。
		// 显式把 WWW-Authenticate 列入响应白名单时仍按配置转发。
		authorizationForwarded := dh.forwardReqHeaders[http.CanonicalHeaderKey("Authorization")]
		if dh.forwardRespHeaders[http.CanonicalHeaderKey("WWW-Authenticate")] ||
			(response.StatusCode == http.StatusUnauthorized && authorizationForwarded) {
			for _, value := range response.Header.Values("WWW-Authenticate") {
				w.Header().Add("WWW-Authenticate", value)
			}
		}
		slog.Error(fmt.Sprintf("Request failed: %s - %s", downUrl, response.Status))
		http.Error(w, "Request failed: "+response.Status, response.StatusCode)
		return -1
	}

	// 未指定文件名时，优先使用上游 Content-Disposition 中的文件名
	if *filename == "" {
		*filename = filenameFromContentDisposition(response.Header.Get("Content-Disposition"))
	}
	if *filename == "" {
		baseURL := request.URL
		if response.Request != nil && response.Request.URL != nil {
			baseURL = response.Request.URL
		}
		*filename = sanitizeFilename(defaultFilename(baseURL))
	}

	// 透传响应头给客户端
	dh.copyForwardResponseHeaders(w, response.Header, true)

	// 设置响应头
	w.Header().Set("Content-Disposition", formatContentDisposition(*filename))
	if ct := w.Header().Get("Content-Type"); ct == "" {
		// 如果响应头没有Content-Type，则默认为二进制流
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	// 透传上游状态码：206 Partial Content 等非 200 的 2xx 必须显式写入，
	// 否则客户端会拿到 200 + 部分内容，误以为文件已完整
	w.WriteHeader(response.StatusCode)

	// HEAD 请求只需要响应头
	if r.Method == http.MethodHead {
		if response.ContentLength >= 0 {
			return response.ContentLength
		}
		return 0
	}

	// 将响应体写入到ResponseWriter
	written, err := io.Copy(w, response.Body)
	if err != nil {
		slog.Error(fmt.Sprintf("Copy url data error: %v", err))
		return -1
	}
	return written
}

// copyForwardResponseHeaders 将白名单内的上游响应头复制给客户端。
// withBody 为 false 时跳过与响应体相关的头，用于 304 等没有响应体的响应。
func (dh *DownloadHandler) copyForwardResponseHeaders(w http.ResponseWriter, header http.Header, withBody bool) {
	for name, values := range header {
		if !dh.forwardRespHeaders[name] {
			continue
		}
		if !withBody {
			switch name {
			case "Content-Length", "Content-Encoding", "Content-Range":
				continue
			}
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
}

// 下载本地文件
func (dh *DownloadHandler) downloadFile(w http.ResponseWriter, r *http.Request, downPath string, filename string) int64 {
	// downPath 是 url.Parse 解码后的路径，去掉前导斜杠后必须是下载目录内的相对路径。
	// 使用 filepath.IsLocal 拒绝绝对路径和 .. 跳出，再用 os.Root 限制实际打开范围。
	relPath := strings.TrimPrefix(downPath, "/")
	if relPath == "" || !filepath.IsLocal(filepath.FromSlash(relPath)) {
		http.Error(w, "Invalid file path", http.StatusBadRequest)
		return -1
	}

	root, err := os.OpenRoot(dh.dir)
	if err != nil {
		slog.Error(fmt.Sprintf("Open root dir error: %v", err))
		http.Error(w, "File not found", http.StatusNotFound)
		return -1
	}
	defer func() {
		_ = root.Close()
	}()

	// 打开文件
	file, err := root.Open(filepath.FromSlash(relPath))
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return -1
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	fileInfo, err := file.Stat()
	if err != nil {
		http.Error(w, "File stat error", http.StatusInternalServerError)
		return -1
	}
	if fileInfo.IsDir() {
		http.Error(w, "File not found", http.StatusNotFound)
		return -1
	}

	// 设置响应头
	w.Header().Set("Content-Disposition", formatContentDisposition(filename))
	// ServeContent 会自动处理304相关的判断和响应
	http.ServeContent(w, r, fileInfo.Name(), fileInfo.ModTime(), file)
	return fileInfo.Size()
}

// 根据 URL 生成默认下载文件名
func defaultFilename(u *url.URL) string {
	if u.Path != "" {
		// 根路径的 Base 是 "/"，目录路径的 Base 可能是 "." 或 ".."，都不适合作为文件名
		if name := path.Base(u.Path); name != "/" && name != "." && name != ".." {
			return name
		}
	}
	if host := u.Hostname(); host != "" {
		return host
	}
	return "download"
}

// 从上游 Content-Disposition 中提取文件名，作为未指定文件名时的默认值。
// 上游值不可信：去掉路径和控制字符，避免路径穿越与响应头注入。
func filenameFromContentDisposition(value string) string {
	if value == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(value)
	if err != nil {
		return ""
	}
	name := strings.TrimSpace(params["filename"])
	if name == "" {
		return ""
	}
	name = sanitizeFilename(name)
	if name == "" {
		return ""
	}
	return name
}

// sanitizeFilename 只保留文件名的最后一段，移除控制字符并限制长度，
// 避免路径穿越、响应头注入和超长文件名进入日志或 Content-Disposition。
func sanitizeFilename(name string) string {
	if name == "" {
		return ""
	}
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if utf8.RuneCountInString(name) > maxFilenameRunes {
		name = string([]rune(name)[:maxFilenameRunes])
	}
	if name == "." || name == ".." || name == "/" {
		return ""
	}
	return name
}

// 生成 Content-Disposition 头值，非 ASCII 文件名按 RFC 2231 编码
func formatContentDisposition(filename string) string {
	if filename == "" {
		filename = "download"
	}
	return mime.FormatMediaType("attachment", map[string]string{"filename": filename})
}

// constantTimeEqual 以恒定时间比较两个字符串。先做哈希再比较，避免长度差异泄漏。
func constantTimeEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

// 返回JSON格式的响应，HTTP 状态码与响应体内的 code 保持一致
func (dh *DownloadHandler) jsonResponse(w http.ResponseWriter, code int, msg string, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	response := map[string]any{
		"code": code,
		"msg":  msg,
		"data": data,
	}
	return json.NewEncoder(w).Encode(response)
}
