package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
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

type testServer struct {
	tb       testing.TB
	laddr    string
	question string

	s      *Server
	remote *dns.Server
}

func (ts *testServer) exchange(logmsg string, wantIP string) {
	ts.tb.Helper()
	var c dns.Client
	var m dns.Msg
	m.SetQuestion(ts.question, dns.TypeMX)
	gotr, _, err := c.Exchange(&m, ts.laddr)
	if err != nil {
		ts.tb.Fatalf("%s: cannot contact server: %v", logmsg, err)
	}
	if got, want := len(gotr.Answer), 1; got != want {
		ts.tb.Fatalf("%s: answer length: got %d want %d", logmsg, got, want)
	}
	if got := gotr.Answer[0].String(); !strings.Contains(got, ts.question) || !strings.Contains(got, wantIP) {
		ts.tb.Errorf("%s: response:\ngot: %q\nwant: \"%s...%s\"", logmsg, got, ts.question, wantIP)
	}
}

func setupTestServer(tb testing.TB, cacheSize int, responder func(q string) string) (ts *testServer, cleanup func()) {
	const raddr = "gopher.empijei:853"
	ts = &testServer{
		tb:       tb,
		question: "raccoon.miki.",
		laddr:    "127.0.0.1:5678",
	}

	// Setup fake remote
	flst := newFakeListener(raddr)
	{
		ts.remote = &dns.Server{
			Addr:     raddr,
			Listener: flst,
			Handler: fakeServer(func(w dns.ResponseWriter, q *dns.Msg) {
				if got := q.String(); !strings.Contains(got, ts.question) {
					tb.Errorf("Got unexpected question: %q want it to contain %q", got, ts.question)
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
				_ = w.WriteMsg(m)
			}),
		}
		go func() {
			if err := ts.remote.ActivateAndServe(); err != nil {
				tb.Errorf("Cannot ActivateAndServe: %v", err)
			}
		}()
	}

	// Setup Server
	ctx, cancel := context.WithCancel(context.Background())
	{
		ts.s = NewServer(cacheSize, false, raddr)
		ts.s.dial = flst.dialer()
		go func() {
			if err := ts.s.Run(ctx, ts.laddr); err != nil {
				tb.Errorf("Cannot run Server: %v", err)
			}
		}()
		// TODO find a way to report the server has started
		time.Sleep(1 * time.Second)
	}

	if tb.Failed() {
		tb.Fatalf("Test failed during setup, aborting.")
	}

	return ts, func() {
		flst.Close()
		cancel()
	}
}

func TestServer(t *testing.T) {
	ts, cleanup := setupTestServer(t, 0, nil)
	defer cleanup()
	for _, v := range []string{"Network", "Cache"} {
		ts.exchange(v, "42.42.42.42")
	}
}

func BenchmarkServerHit(b *testing.B) {
	ts, cleanup := setupTestServer(b, 0, nil)
	defer cleanup()
	// Pre-fill cache
	ts.exchange("bench", "42.42.42.42")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ts.exchange("bench", "42.42.42.42")
	}
}
func BenchmarkServerNoCache(b *testing.B) {
	ts, cleanup := setupTestServer(b, -1, nil)
	defer cleanup()
	// Pre-fill cache
	ts.exchange("bench", "42.42.42.42")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ts.exchange("bench", "42.42.42.42")
	}
}

func TestCache(t *testing.T) {
	var mu sync.Mutex
	resp := "raccoon.miki. 2311 IN A 42.42.42.42"
	ts, cleanup := setupTestServer(t, -1, func(string) string {
		mu.Lock()
		defer mu.Unlock()
		return resp
	})
	defer cleanup()
	// First, let's verify we can fill the cache.
	ts.exchange("cachefill", "42.42.42.42")
	// Now change upstream and make sure we hit the cache and get the old value.
	mu.Lock()
	resp = "raccoon.miki. 2311 IN A 43.43.43.43"
	mu.Unlock()
	ts.exchange("hit", "43.43.43.43")
}

func TestDebugHandler(t *testing.T) {
	type testData struct {
		CacheMetrics       specialized.CacheMetrics
		CacheLen, CacheCap int
		Uptime             string
	}

	tests := []struct {
		name         string
		size         int
		reqs         int
		evictMetrics bool
		want         testData
	}{
		{
			name: "no cache",
			want: testData{CacheCap: defaultCacheSize},
		},
		{
			name: "cache",
			size: 100,
			reqs: 10,
			want: testData{
				CacheMetrics: specialized.CacheMetrics{MissMFA: 10, HitLRU: 9, MissLRU: 1, Miss: 1},
				CacheLen:     1, CacheCap: 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts, cleanup := setupTestServer(t, tt.size, nil)
			defer cleanup()
			var (
				h = ts.s.DebugHandler()
				w = httptest.NewRecorder()
				r = httptest.NewRequest("GET", "/", nil)
			)
			for i := 0; i < tt.reqs; i++ {
				ts.exchange(strconv.Itoa(i), "42.42.42.42")
			}
			h.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("HTTP status: got %d want 200", w.Code)
			}
			buf, err := ioutil.ReadAll(w.Body)
			if err != nil {
				t.Fatalf("Can't read HTTP response: %v", err)
			}
			got := testData{}
			if err := json.Unmarshal(buf, &got); err != nil {
				t.Fatalf("Can't unmarshal HTTP response: %v", err)
			}
			// Intentionally ignoring Uptime for tests
			if got.Uptime = ""; got != tt.want {
				t.Errorf("newServer(%v,%v).DebugHandler(): %d requests, got\n%+v\nwant\n%+v", tt.size, tt.evictMetrics, tt.reqs, got, tt.want)
			}
		})
	}
}
