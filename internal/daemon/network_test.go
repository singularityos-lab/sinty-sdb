package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestOnAPublicNetworkOnlyTheCableIsAdmitted(t *testing.T) {
	kind := filepath.Join(t.TempDir(), "network-kind")
	links := map[string]string{"192.168.1.5": "wlan0", "172.16.42.1": "usb0"}
	admit := PrivateNetworkOnly(kind, func(ip net.IP) string { return links[ip.String()] })
	at := func(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 5555} }
	peer := at("192.168.1.9")
	if !admit(at("192.168.1.5"), peer) {
		t.Fatal("refused before sinty-nm said anything: recovery would lose its channel")
	}
	for kindText, wifi := range map[string]bool{"home\n": true, "work": true, "none": true, "public\n": false} {
		os.WriteFile(kind, []byte(kindText), 0o644)
		if got := admit(at("192.168.1.5"), peer); got != wifi {
			t.Errorf("%q over wifi: admitted %v", kindText, got)
		}
		if !admit(at("172.16.42.1"), at("172.16.42.2")) {
			t.Errorf("%q over the cable: refused", kindText)
		}
	}
}
