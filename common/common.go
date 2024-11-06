package common

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// CalculateMD5 计算传入字符串的MD5值，返回小写的MD5值
func CalculateMD5(input string) string {
	if input == "" {
		return ""
	}
	// 创建 MD5 散列
	hash := md5.New()
	// 将字符串转换为字节数组并写入散列
	hash.Write([]byte(input))
	// 计算 MD5 哈希值
	hashInBytes := hash.Sum(nil)
	// 将字节数组转换为十六进制字符串
	md5String := hex.EncodeToString(hashInBytes)
	return md5String
}

// FormatBytes 格式化byte字节大小为人类直观的可读格式
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// GetRealIP 获取请求的真实IP地址
func GetRealIP(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	realIP := r.Header.Get("X-Real-IP")

	// X-Forwarded-For可能包含多个IP地址，第一个是真实IP
	if forwardedFor != "" {
		ips := strings.Split(forwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}

	// 如果X-Forwarded-For为空，使用X-Real-IP
	if realIP != "" {
		return realIP
	}

	// 如果都为空，直接获取RemoteAddr
	addr := r.RemoteAddr

	// 查找冒号的位置
	colonIndex := strings.LastIndex(addr, ":")

	// 如果找到了冒号，提取IP地址部分
	if colonIndex != -1 {
		addr = addr[:colonIndex]
	}

	// 处理可能存在的方括号
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		addr = addr[1 : len(addr)-1]
	}

	return addr
}
