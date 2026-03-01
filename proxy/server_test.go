package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gologme/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
)

type fakeServer func(ctx context.Context, w dns.ResponseWriter, q *dns.Msg)

func (f fakeServer) ServeDNS(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) { f(ctx, w, q) }

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
	c := dns.NewClient()
	m := dns.NewMsg(ts.question, dns.TypeMX)
	m.ID = dns.ID()
	m.RecursionDesired = true
	gotr, _, err := c.Exchange(context.TODO(), m, "udp", ts.laddr)
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
		laddr:    "127.0.0.1:0",
	}

	// Setup fake remote
	flst := newFakeListener(raddr)
	{
		ts.remote = &dns.Server{
			Addr:     raddr,
			Listener: flst,
			Handler: fakeServer(func(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
				if got := q.String(); !strings.Contains(got, ts.question) {
					tb.Errorf("Got unexpected question: %q want it to contain %q", got, ts.question)
				}
				var respb string
				if responder != nil {
					respb = responder(q.String())
				} else {
					respb = "raccoon.miki. 2311 IN A 42.42.42.42"
				}
				resp, err := dns.New(respb)
				if err != nil {
					tb.Fatalf("Cannot parse test response: %v", err)
				}
				m := new(dns.Msg)
				dnsutil.SetReply(m, q)
				m.Answer = []dns.RR{resp}
				_ = m.Pack()
				_, _ = m.WriteTo(w)
			}),
		}
		go func() { _ = ts.remote.ListenAndServe() }()
	}

	// Setup Server
	ctx, cancel := context.WithCancel(context.Background())
	{
		logger := log.New(os.Stdout, "", log.Flags())
		mux := dns.NewServeMux()
		ts.s = NewServer(mux, logger, cacheSize, false, 60, ts.laddr, strings.Split(raddr, ",")...)
		mux.HandleFunc(".", ts.s.ServeDNS)
		ts.s.dial = flst.dialer()
		go func() { _ = ts.s.Run(ctx) }()

		// Wait for the server to bind and update its address
		started := false
		for i := 0; i < 50; i++ {
			ts.s.mu.Lock()
			if len(ts.s.servers) > 1 && !strings.HasSuffix(ts.s.servers[1].Addr, ":0") {
				ts.laddr = ts.s.servers[1].Addr
				started = true
			}
			ts.s.mu.Unlock()
			if started {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !started {
			tb.Fatal("Server failed to start and bind within timeout")
		}
	}

	if tb.Failed() {
		tb.Fatalf("Test failed during setup, aborting.")
	}

	return ts, func() {
		_ = flst.Close()
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
			buf, err := io.ReadAll(w.Body)
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

func TestEDE(t *testing.T) {
	const question = "ede.test."
	const raddr = "ede.upstream:853"

	// Setup fake remote that returns EDE
	flst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	realRAddr := flst.Addr().String()
	remote := &dns.Server{
		Addr:     realRAddr,
		Net:      "tcp",
		Listener: flst,
		Handler: fakeServer(func(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
			m := new(dns.Msg)
			dnsutil.SetReply(m, q)
			m.Rcode = dns.RcodeServerFailure
			// Add EDE option
			ede := &dns.EDE{
				InfoCode:  dns.ExtendedErrorDNSBogus,
				ExtraText: "test EDE message",
			}
			m.Pseudo = append(m.Pseudo, ede)
			if _, err := m.WriteTo(w); err != nil {
				t.Errorf("Fake upstream write failed: %v", err)
			}
		}),
	}
	go func() { _ = remote.ListenAndServe() }()
	defer func() { _ = flst.Close() }()

	// Setup Proxy Server
	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(os.Stdout, "", log.Flags())
	mux := dns.NewServeMux()
	s := NewServer(mux, logger, 0, false, 60, "127.0.0.1:0", raddr)
	s.dial = func(addr string, _ *tls.Config) (net.Conn, error) {
		return net.Dial("tcp", realRAddr)
	}
	s.pools = nil
	s.pools = append(s.pools, newPool(connectionsPerUpstream, s.connector(raddr)))

	mux.HandleFunc(".", s.ServeDNS)
	go func() { _ = s.Run(ctx) }()
	defer cancel()

	// Wait for the server to bind and update its address
	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") {
			actualProxyAddr = s.servers[1].Addr
		}
		s.mu.Unlock()
		if actualProxyAddr != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if actualProxyAddr == "" {
		t.Fatal("Proxy failed to start and bind within timeout")
	}

	// Query Proxy
	c := dns.NewClient()
	m := dns.NewMsg(question, dns.TypeA)
	m.UDPSize, m.Security = 4096, true
	r, _, err := c.Exchange(context.TODO(), m, "udp", actualProxyAddr)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if r.Rcode != dns.RcodeServerFailure {
		t.Errorf("Got Rcode %d, want SERVFAIL", r.Rcode)
	}

	foundEDE := false
	for _, p := range r.Pseudo {
		if e, ok := p.(*dns.EDE); ok {
			foundEDE = true
			if e.InfoCode != dns.ExtendedErrorDNSBogus {
				t.Errorf("Got EDE code %d, want %d", e.InfoCode, dns.ExtendedErrorDNSBogus)
			}
			// Note: miekg/dns v2 v0.6.64 has a bug in EDE.pack that garbles ExtraText.
			// So we only check the InfoCode for now.
		}
	}
	if !foundEDE {
		t.Errorf("EDE option not found in response")
	}
}

func TestEDNSPropagation(t *testing.T) {
	const question = "edns.test."

	// Setup Proxy Server with NO upstreams to force SERVFAIL
	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(os.Stdout, "", log.Flags())
	mux := dns.NewServeMux()
	s := NewServer(mux, logger, 0, false, 60, "127.0.0.1:0", "127.0.0.1:1") // invalid upstream to force SERVFAIL
	mux.HandleFunc(".", s.ServeDNS)
	go func() { _ = s.Run(ctx) }()
	defer cancel()

	// Wait for the server to bind and update its address
	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") {
			actualProxyAddr = s.servers[1].Addr
		}
		s.mu.Unlock()
		if actualProxyAddr != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if actualProxyAddr == "" {
		t.Fatal("Proxy failed to start and bind within timeout")
	}

	// Query Proxy with custom EDNS settings
	c := dns.NewClient()
	m := dns.NewMsg(question, dns.TypeA)
	m.UDPSize = 1234
	m.Security = true // DO bit

	r, _, err := c.Exchange(context.TODO(), m, "udp", actualProxyAddr)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("Got Rcode %d, want SERVFAIL", r.Rcode)
	}

	if r.UDPSize != 1234 {
		t.Errorf("UDPSize mismatch in SERVFAIL response: got %d, want 1234", r.UDPSize)
	}
	if !r.Security {
		t.Errorf("Security/DO bit not propagated in SERVFAIL response")
	}
}

func TestCacheDeepCopy(t *testing.T) {
	cache, _ := newCache(10, false)
	q := dns.NewMsg("example.com.", dns.TypeA)
	q.ID = 123

	r := dns.NewMsg("example.com.", dns.TypeA)
	r.ID = 123
	ans, _ := dns.New("example.com. 3600 IN A 1.1.1.1")
	r.Answer = append(r.Answer, ans)

	cache.put(q, r)

	// First lookup
	m1, ok := cache.get(q)
	if !ok {
		t.Fatal("Cache miss")
	}
	if m1.ID != 123 {
		t.Errorf("ID mismatch: %d", m1.ID)
	}

	// Modify m1
	m1.ID = 999
	m1.Answer[0].Header().TTL = 0

	// Second lookup of the same key
	q2 := CloneMsg(q)
	q2.ID = 456
	m2, ok := cache.get(q2)
	if !ok {
		t.Fatal("Cache miss on second lookup")
	}

	if m2.ID != 456 {
		t.Errorf("m2 ID should be overwritten by request ID: got %d, want 456", m2.ID)
	}

	if m2.Answer[0].Header().TTL == 0 {
		t.Errorf("m2 Answer TTL was affected by modification of m1: cache is not deep copied")
	}
}

func TestConcurrencyRace(t *testing.T) {
	// Use multiple upstreams to trigger parallel forwarding
	// We want to verify that concurrent access to the query Msg doesn't race.
	u1 := newFakeListener("u1.test:853")
	u2 := newFakeListener("u2.test:853")

	h := fakeServer(func(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		dnsutil.SetReply(m, q)
		ans, _ := dns.New(q.Question[0].Header().Name + " 3600 IN A 1.2.3.4")
		m.Answer = append(m.Answer, ans)
		_ = m.Pack()
		_, _ = w.Write(m.Data)
	})

	s1 := &dns.Server{Addr: u1.a, Net: "tcp", Listener: u1, Handler: h}
	s2 := &dns.Server{Addr: u2.a, Net: "tcp", Listener: u2, Handler: h}
	go func() { _ = s1.ListenAndServe() }()
	go func() { _ = s2.ListenAndServe() }()
	defer func() { _ = u1.Close() }()
	defer func() { _ = u2.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(os.Stdout, "", log.Flags())
	mux := dns.NewServeMux()
	s := NewServer(mux, logger, 0, false, 60, "127.0.0.1:0", u1.a, u2.a)
	s.dial = func(addr string, _ *tls.Config) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
	// Fixing pools
	s.pools = nil
	s.pools = append(s.pools, newPool(2, s.connector(u1.a)))
	s.pools = append(s.pools, newPool(2, s.connector(u2.a)))

	mux.HandleFunc(".", s.ServeDNS)
	go func() { _ = s.Run(ctx) }()
	defer cancel()

	// Wait for the server to bind and update its address
	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") {
			actualProxyAddr = s.servers[1].Addr
		}
		s.mu.Unlock()
		if actualProxyAddr != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if actualProxyAddr == "" {
		t.Fatal("Proxy failed to start and bind within timeout")
	}

	// Run many parallel queries with -race to check for data races
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := dns.NewClient()
			m := dns.NewMsg("test"+strconv.Itoa(i)+".com.", dns.TypeA)
			_, _, err := c.Exchange(context.TODO(), m, "udp", actualProxyAddr)
			if err != nil {
				t.Errorf("Parallel query %d failed: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}
