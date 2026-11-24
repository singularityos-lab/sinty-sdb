package daemon

import (
	"net"
	"os"
	"strings"
)

const NetworkKindPath = "/run/sinty-nm/network-kind"

var cableLinks = []string{"usb", "rndis", "ncm"}

func PrivateNetworkOnly(kindPath string, linkOf func(net.IP) string) func(local, remote net.Addr) bool {
	return func(local, remote net.Addr) bool {
		b, err := os.ReadFile(kindPath)
		if err != nil || strings.TrimSpace(string(b)) != "public" {
			return true
		}
		t, ok := local.(*net.TCPAddr)
		if !ok {
			return false
		}
		name := linkOf(t.IP)
		for _, p := range cableLinks {
			if strings.HasPrefix(name, p) {
				return true
			}
		}
		return false
	}
}

func LinkOf(ip net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return i.Name
			}
		}
	}
	return ""
}
