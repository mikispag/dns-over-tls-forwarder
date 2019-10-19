package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func init() { resolutionMilliseconds = 1 }

type fakeServer func(w dns.ResponseWriter, q *dns.Msg)

func (f fakeServer) ServeDNS(w dns.ResponseWriter, q *dns.Msg) { f(w, q) }

type fakeAddr string

func (f fakeAddr) Network() string { return string(f) }
func (f fakeAddr) String() string  { return string(f) }

type fakeListener struct {
	a string
	c chan net.Conn
	e chan error
}

func newFakeListener(a string) fakeListener {
	return fakeListener{a, make(chan net.Conn), make(chan error)}
}
func (f fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.c:
		return c, nil
	case err, ok := <-f.e:
		if !ok {
			return nil, io.EOF
		}
		return nil, err
	}
}
func (f fakeListener) Close() error   { f.e <- io.EOF; return nil }
func (f fakeListener) Addr() net.Addr { return fakeAddr(f.a) }
func (f fakeListener) connect() net.Conn {
	l, r := net.Pipe()
	f.c <- r
	return l
}
func (f fakeListener) dialer() func(addr string, c *tls.Config) (net.Conn, error) {
	return func(addr string, _ *tls.Config) (net.Conn, error) {
		// TODO assert the tls config is correct.
		if addr == f.a {
			return f.connect(), nil
		}
		return nil, fmt.Errorf("connect to %q, want %q", addr, f.a)
	}
}

func setupTestServer(tb testing.TB, cacheSize int, responder func(q string) string) (exchanger func(logPrefix string), cleanup func()) {
	tb.Helper()
	const (
		raddr    = "gopher.empijei:853"
		laddr    = "127.0.0.1:5678"
		question = "raccoon.miki."
		ip       = "42.42.42.42"
	)

	// WARNING: Do not use defer in this function, all cleanups should be put in the cleanup func at the end.

	flst := newFakeListener(raddr)
	rems := &dns.Server{
		Addr:     raddr,
		Listener: flst,
		Handler: fakeServer(func(w dns.ResponseWriter, q *dns.Msg) {
			if got := q.String(); !strings.Contains(got, question) {
				tb.Errorf("Got unexpected question: %q want it to contain %q", got, question)
			}
			var respb string
			if responder != nil {
				respb = responder(q.String())
			} else {
				respb = "raccoon.miki. 2311 IN A 42.42.42.42"
			}
			resp, err := dns.NewRR(respb)
			if err != nil {
				tb.Fatalf("Cannot parse test response: %v", err)
			}
			m := &dns.Msg{}
			m = m.SetReply(q)
			m.Answer = []dns.RR{resp}
			w.WriteMsg(m)
		}),
	}
	go rems.ActivateAndServe()

	ctx, cancel := context.WithCancel(context.Background())
	srv := NewServer(cacheSize, false, raddr)
	srv.dial = flst.dialer()
	go srv.Run(ctx, laddr)
	// TODO find a way to report the server has started
	time.Sleep(50 * time.Millisecond)

	exchange := func(v string) {
		var c dns.Client
		var m dns.Msg
		m.SetQuestion(question, dns.TypeMX)
		gotr, _, err := c.Exchange(&m, laddr)
		if err != nil {
			tb.Fatalf("%s: cannot contact server: %v", v, err)
		}
		if got, want := len(gotr.Answer), 1; got != want {
			tb.Fatalf("%s: answer length: got %d want %d", v, got, want)
		}
		if got := gotr.Answer[0].String(); !strings.Contains(got, question) || !strings.Contains(got, ip) {
			tb.Errorf("%s: response:\ngot: %q\nwant: \"%s...%s\"", v, got, question, ip)
		}
	}

	return exchange, func() {
		flst.Close()
		cancel()
	}

}

func TestServer(t *testing.T) {
	exchange, cleanup := setupTestServer(t, 0, nil)
	defer cleanup()
	for _, v := range []string{"Network", "Cache"} {
		exchange(v)
	}
}

func BenchmarkServerHit(b *testing.B) {
	exchange, cleanup := setupTestServer(b, 0, nil)
	defer cleanup()
	// Pre-fill cache
	exchange("bench")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		exchange("bench")
	}
}
func BenchmarkServerNoCache(b *testing.B) {
	exchange, cleanup := setupTestServer(b, -1, nil)
	defer cleanup()
	// Pre-fill cache
	exchange("bench")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		exchange("bench")
	}
}

func TestCache(t *testing.T) {
	var mu sync.Mutex
	resp := "raccoon.miki. 2311 IN A 42.42.42.42"
	exchange, cleanup := setupTestServer(t, -1, func(string) string {
		mu.Lock()
		defer mu.Unlock()
		return resp
	})
	defer cleanup()
	// First, let's verify we can fill the cache.
	exchange("cachefill")
	// Now change upstream and make sure we hit the cache and get the old value.
	mu.Lock()
	resp = "raccoon.miki. 2311 IN A 43.43.43.43"
	mu.Unlock()
	exchange("hit")
}
