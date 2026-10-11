package netinfo

import (
	"context"
	"net"
	"os"
	"strings"
)

var vpnPatterns = []string{
	"tun", "tap", "wg", "utun", "ppp", "ipsec", "vpn", "wireguard", "openvpn", "wintun",
	"amnezia", "outline", "proton", "nord", "tailscale", "zerotier", "warp", "sing-box", "clash", "v2ray", "xray",
}

var cellularPatterns = []string{
	"wwan", "rmnet", "ccmni", "pdp_ip", "cellular", "mobile broadband", "rndis", "сотов", "мобильн",
}

// LocalInfo describes the interface that carries the default route.
type LocalInfo struct {
	Interface string
	VPN       bool
	VPNReason string
	Cellular  bool
	CGNAT     bool
}

// DetectLocal inspects the default-route interface. It sends no packets:
// connecting a UDP socket only consults the routing table.
func DetectLocal() LocalInfo {
	var li LocalInfo
	var d net.Dialer
	c, err := d.DialContext(context.Background(), "udp", "198.18.0.1:53")
	if err != nil {
		return li
	}
	local, _ := c.LocalAddr().(*net.UDPAddr)
	_ = c.Close()
	if local == nil {
		return li
	}
	if _, cg, _ := net.ParseCIDR("100.64.0.0/10"); cg.Contains(local.IP) {
		li.CGNAT = true
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return li
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(local.IP) {
				li.Interface = ifc.Name
				classifyInterface(&li, ifc)
				return li
			}
		}
	}
	return li
}

func classifyInterface(li *LocalInfo, ifc net.Interface) {
	name := strings.ToLower(ifc.Name)
	for _, p := range vpnPatterns {
		if strings.Contains(name, p) {
			li.VPN = true
			li.VPNReason = "interface " + ifc.Name
			break
		}
	}
	if !li.VPN && ifc.Flags&net.FlagPointToPoint != 0 {
		li.VPN = true
		li.VPNReason = "point-to-point interface " + ifc.Name
	}
	for _, p := range cellularPatterns {
		if strings.Contains(name, p) {
			li.Cellular = true
			break
		}
	}
}

// ProxyEnvSet reports whether proxy variables are present in the environment.
func ProxyEnvSet() bool {
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if os.Getenv(v) != "" {
			return true
		}
	}
	return false
}
