// Package testnet provides loopback addresses for tests that start a DNS
// server.
package testnet

import (
	"net"
	"testing"
)

// DNSAddr returns a 127.0.0.1 address whose port is free for both UDP and
// TCP. Binding UDP to a TCP-chosen ephemeral port fails intermittently on
// Windows, which can reserve a port for one protocol but not the other.
func DNSAddr(tb testing.TB) string {
	tb.Helper()
	for range 50 {
		udp, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			tb.Fatal(err)
		}
		addr := udp.LocalAddr().String()
		tcp, err := net.Listen("tcp", addr)
		_ = udp.Close()
		if err == nil {
			_ = tcp.Close()
			return addr
		}
	}
	tb.Fatal("no loopback port is free for both UDP and TCP")
	return ""
}
