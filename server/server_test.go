package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

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

func TestServer(t *testing.T) {
	const (
		raddr    = "gopher.empijei:53"
		laddr    = "127.0.0.1:5678"
		question = "raccoon.miki."
		ip       = "42.42.42.42"
		respb    = "raccoon.miki. 2311 IN A 42.42.42.42"
	)
	resp, err := dns.NewRR(respb)
	if err != nil {
		t.Fatalf("Cannot parse test response: %v", err)
	}

	flst := newFakeListener(raddr)
	defer flst.Close()
	rems := &dns.Server{
		Addr:     raddr,
		Listener: flst,
		Handler: fakeServer(func(w dns.ResponseWriter, q *dns.Msg) {
			m := &dns.Msg{}
			m = m.SetReply(q)
			m.Answer = []dns.RR{resp}
			w.WriteMsg(m)
		}),
	}
	go rems.ActivateAndServe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := New(raddr)
	srv.dial = flst.dialer()
	go srv.Run(ctx, laddr)
	// TODO find a way to report the server has started
	time.Sleep(50 * time.Millisecond)
	var c dns.Client
	var m dns.Msg
	m.SetQuestion(question, dns.TypeMX)
	// Query twice, once to hit the resolve, once for the cache.
	for _, v := range []string{"Network", "Cache"} {
		gotr, _, err := c.Exchange(&m, laddr)
		if err != nil {
			t.Fatalf("%s: cannot contact server: %v", v, err)
		}
		if got, want := len(gotr.Answer), 1; got != want {
			t.Fatalf("%s: answer length: got %d want %d", v, got, want)
		}
		if got := gotr.Answer[0].String(); !strings.Contains(got, question) || !strings.Contains(got, ip) {
			t.Errorf("%s: response:\ngot: %q\nwant: \"%s...%s\"", v, got, question, ip)
		}
	}
}
