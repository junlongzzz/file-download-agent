package handler

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"0.1.2.3",            // 0.0.0.0/8
		"10.0.0.1",           // 私网
		"100.64.0.1",         // 运营商级 NAT
		"127.0.0.1",          // 回环
		"169.254.169.254",    // 链路本地（云元数据）
		"172.16.0.1",         // 私网
		"192.0.0.9",          // IETF 协议分配
		"192.168.1.1",        // 私网
		"198.18.0.1",         // 网络基准测试
		"168.63.129.16",      // Azure wireserver
		"224.0.0.1",          // 组播
		"240.0.0.1",          // 保留
		"255.255.255.255",    // 广播
		"::",                 // 未指定
		"::1",                // IPv6 回环
		"::ffff:127.0.0.1",   // IPv4-mapped IPv6
		"fc00::1",            // IPv6 唯一本地地址
		"fe80::1",            // IPv6 链路本地
		"64:ff9b::a9fe:a9fe", // NAT64 嵌入 169.254.169.254
		"64:ff9b::c0a8:101",  // NAT64 嵌入 192.168.1.1
		"64:ff9b::7f00:1",    // NAT64 嵌入 127.0.0.1
		"64:ff9b:1::1",       // 本地使用 NAT64
		"2001::1",            // Teredo
		"2002:7f00:1::",      // 6to4 嵌入 127.0.0.1
		"100::1",             // 丢弃专用地址
	}
	for _, s := range blocked {
		if ip := net.ParseIP(s); !isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%s) = false, want true", s)
		}
	}

	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"2606:4700:4700::1111",
		"64:ff9b::5db8:d822", // NAT64 嵌入 93.184.216.34
	}
	for _, s := range allowed {
		if ip := net.ParseIP(s); isBlockedIP(ip) {
			t.Errorf("isBlockedIP(%s) = true, want false", s)
		}
	}
}

// 非 ASCII 域名必须先转换为 punycode 再解析，否则预检查会误报解析失败。
func TestHostForLookup(t *testing.T) {
	got, err := hostForLookup("bücher.de")
	if err != nil {
		t.Fatalf("hostForLookup() error = %v", err)
	}
	if got != "xn--bcher-kva.de" {
		t.Fatalf("hostForLookup() = %q, want %q", got, "xn--bcher-kva.de")
	}

	got, err = hostForLookup("example.com")
	if err != nil {
		t.Fatalf("hostForLookup() error = %v", err)
	}
	if got != "example.com" {
		t.Fatalf("hostForLookup() = %q, want %q", got, "example.com")
	}
}
