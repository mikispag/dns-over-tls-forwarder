package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func BenchmarkPoolReuse(b *testing.B) {
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	dials := 0
	p := newPool(1, func(context.Context) (net.Conn, error) {
		dials++
		return client, nil
	})
	defer p.shutdown()
	ctx := context.Background()
	c, err := p.get(ctx)
	if err != nil {
		b.Fatal(err)
	}
	p.put(c)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c, err := p.get(ctx)
		if err != nil {
			b.Fatal(err)
		}
		p.put(c)
	}
	b.StopTimer()
	if dials != 1 {
		b.Fatalf("reuse dialed %d connections", dials)
	}
}

var benchmarkClonedMessage *dns.Msg

func BenchmarkCloneMsg(b *testing.B) {
	for _, count := range []int{1, 32} {
		b.Run(fmt.Sprintf("answers=%d", count), func(b *testing.B) {
			q := dns.NewMsg("example.org.", dns.TypeA)
			m := new(dns.Msg)
			dnsutil.SetReply(m, q)
			for i := 0; i < count; i++ {
				rr, err := dns.New(fmt.Sprintf("example.org. 300 IN A 192.0.2.%d", i+1))
				if err != nil {
					b.Fatal(err)
				}
				m.Answer = append(m.Answer, rr)
			}
			if err := m.Pack(); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchmarkClonedMessage = CloneMsg(m)
			}
		})
	}
}
