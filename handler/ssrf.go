package handler

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/net/idna"
)

// errPrivateNetwork 表示目标地址属于禁止访问的内网或保留网段
var errPrivateNetwork = errors.New("target address is in a private or reserved network")

// mustParseCIDRs 解析 CIDR 列表，配置错误时直接 panic
func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		nets = append(nets, network)
	}
	return nets
}

// blockedIPv4Nets 是不允许访问的 IPv4 保留网段。
// 回环、私网、链路本地、组播等由 isBlockedIP 中的 net.IP 方法判断。
var blockedIPv4Nets = mustParseCIDRs(
	"0.0.0.0/8",        // 本网络
	"100.64.0.0/10",    // 运营商级 NAT
	"168.63.129.16/32", // Azure wireserver，可访问实例元数据与主机代理
	"192.0.0.0/24",     // IETF 协议分配
	"198.18.0.0/15",    // 网络基准测试
	"240.0.0.0/4",      // 保留地址，含 255.255.255.255
)

// blockedIPv6Nets 是不允许访问的 IPv6 特殊网段。
// 6to4 与 Teredo 可以把私有 IPv4 嵌入 IPv6，从而绕过只检查 To4() 的
// IPv4 规则；两者均已废弃，直接整段禁止。64:ff9b:1::/48 是本地 NAT64 前缀。
var blockedIPv6Nets = mustParseCIDRs(
	"2001::/32",      // Teredo
	"2002::/16",      // 6to4
	"64:ff9b:1::/48", // 本地使用 NAT64（RFC 8215）
	"100::/64",       // 丢弃专用地址（RFC 6666）
)

// nat64Net 是 RFC 6052 的 NAT64 前缀，最后 4 字节是嵌入的 IPv4 地址
var nat64Net = mustParseCIDRs("64:ff9b::/96")[0]

// isBlockedIPv4 判断 IPv4 地址是否属于禁止访问的回环、私网、链路本地等地址
func isBlockedIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return true
	}
	// NAT64 嵌入地址等场景不会经过外层 isBlockedIP 的 net.IP 方法判断，
	// 这里必须完整检查一遍，不能只看 CIDR 列表。
	if ip4.IsLoopback() || ip4.IsPrivate() || ip4.IsUnspecified() ||
		ip4.IsLinkLocalUnicast() || ip4.IsLinkLocalMulticast() ||
		ip4.IsInterfaceLocalMulticast() || ip4.IsMulticast() {
		return true
	}
	for _, network := range blockedIPv4Nets {
		if network.Contains(ip4) {
			return true
		}
	}
	return false
}

// isBlockedIP 判断 IP 是否属于禁止访问的内网、回环、链路本地等网段
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// net.IP 的 Is* 方法与 To4 会正确处理 IPv4-mapped IPv6（如 ::ffff:127.0.0.1）
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return isBlockedIPv4(ip4)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return true
	}
	for _, network := range blockedIPv6Nets {
		if network.Contains(ip16) {
			return true
		}
	}
	// NAT64 地址的最后一个 32 位是嵌入的 IPv4，必须按 IPv4 规则再检查，
	// 否则 64:ff9b::a9fe:a9fe 会映射到 169.254.169.254 元数据地址。
	if nat64Net.Contains(ip16) {
		return isBlockedIPv4(net.IP(ip16[12:16]))
	}
	return false
}

// hostForLookup 将非 ASCII 域名转换为 punycode。
// net.DefaultResolver 不做 IDNA 转换，而 http.Transport 在拨号前会转换，
// 因此不转换会让合法的国际化域名在预检查阶段误报解析失败。
func hostForLookup(host string) (string, error) {
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return idna.Lookup.ToASCII(host)
		}
	}
	return host, nil
}

// checkHostIP 解析目标主机并确认所有解析结果都不是内网地址。
// 直接传入 IP 时跳过 DNS 解析。
func checkHostIP(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return errPrivateNetwork
		}
		return nil
	}
	host, err := hostForLookup(host)
	if err != nil {
		return err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return errors.New("no address resolved for host")
	}
	for _, addr := range ips {
		if isBlockedIP(addr.IP) {
			return errPrivateNetwork
		}
	}
	return nil
}

// newRestrictedDialer 返回在建立连接前检查目标 IP 的 dialer。
// 请求前的 DNS 检查与实际拨号之间存在时间差，这里校验实际连接的地址，
// 用于防止 DNS rebinding 绕过。
func newRestrictedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if isBlockedIP(net.ParseIP(host)) {
				return errPrivateNetwork
			}
			return nil
		},
	}
}

// hasProxyEnv 判断是否通过环境变量配置了 HTTP 代理。
// 使用代理时拨号目标是代理本身，拨号层检查会误伤本地代理，因此跳过。
func hasProxyEnv() bool {
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}
