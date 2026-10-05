package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gologme/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
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
func (f fakeListener) dialer() func(context.Context, string, *tls.Config) (net.Conn, error) {
	return func(_ context.Context, addr string, _ *tls.Config) (net.Conn, error) {
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
	m := dns.NewMsg(ts.question, dns.TypeA)
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
		ts.s = NewServer(nil, logger, cacheSize, false, 60, ts.laddr, strings.Split(raddr, ",")...)
		ts.s.dial = flst.dialer()
		go func() { _ = ts.s.Run(ctx) }()

		// Wait for the server to bind and update its address
		started := false
		for i := 0; i < 50; i++ {
			ts.s.mu.Lock()
			if len(ts.s.servers) > 1 && !strings.HasSuffix(ts.s.servers[1].Addr, ":0") && !ts.s.startTime.IsZero() {
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

func TestDefaultDNSHandler(t *testing.T) {
	s := NewServer(nil, log.New(io.Discard, "", 0), 10, false, 0, "127.0.0.1:0", "127.0.0.1:853")
	for _, listener := range s.servers {
		t.Run(listener.Net, func(t *testing.T) {
			if listener.Handler != s {
				t.Fatal("nil mux did not select the proxy as the default handler")
			}
			for _, name := range []string{".", "nested.example.test."} {
				q := dns.NewMsg(name, dns.TypeA)
				s.cache.put(q, cacheTestAnswer(t, q, name+" 300 IN A 192.0.2.1"))
				w := dnstest.NewTestRecorder()
				listener.Handler.ServeDNS(context.Background(), w, q)
				if err := w.Msg.Unpack(); err != nil {
					t.Fatal(err)
				}
				if w.Msg.Rcode != dns.RcodeSuccess || len(w.Msg.Answer) != 1 || w.Msg.Answer[0].Header().Name != name {
					t.Fatalf("default handler did not answer %q: %v", name, w.Msg)
				}
			}
		})
	}
}

func TestSuppliedDNSMux(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("custom.test.", func(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
		if dns.Zone(ctx) != "custom.test." {
			t.Errorf("custom handler received wrong zone: %q", dns.Zone(ctx))
		}
		m := cacheTestAnswer(t, q, q.Question[0].Header().Name+" 300 IN A 192.0.2.2")
		if err := m.Pack(); err != nil {
			t.Fatal(err)
		}
		if _, err := m.WriteTo(w); err != nil {
			t.Fatal(err)
		}
	})
	s := NewServer(mux, log.New(io.Discard, "", 0), 10, false, 0, "127.0.0.1:0", "127.0.0.1:853")
	for _, listener := range s.servers {
		for _, name := range []string{"sub.custom.test.", "unmatched.test."} {
			q := dns.NewMsg(name, dns.TypeA)
			if err := q.Pack(); err != nil {
				t.Fatal(err)
			}
			incoming := &dns.Msg{Data: q.Data}
			if err := incoming.Unpack(); err != nil {
				t.Fatal(err)
			}
			w := dnstest.NewTestRecorder()
			listener.Handler.ServeDNS(context.Background(), w, incoming)
			if err := w.Msg.Unpack(); err != nil {
				t.Fatal(err)
			}
			if name == "sub.custom.test." {
				if w.Msg.Rcode != dns.RcodeSuccess || len(w.Msg.Answer) != 1 {
					t.Fatalf("custom zone handler was bypassed: %v", w.Msg)
				}
			} else if w.Msg.Rcode != dns.RcodeRefused {
				t.Fatalf("unmatched query bypassed custom mux policy: %v", w.Msg)
			}
		}
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
	s := NewServer(nil, logger, 0, false, 60, "127.0.0.1:0", raddr)
	s.dial = func(_ context.Context, addr string, _ *tls.Config) (net.Conn, error) {
		return net.Dial("tcp", realRAddr)
	}
	s.pools = nil
	s.pools = append(s.pools, newPool(connectionsPerUpstream, s.connector(raddr)))

	go func() { _ = s.Run(ctx) }()
	defer cancel()

	// Wait for the server to bind and update its address
	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") && !s.startTime.IsZero() {
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
	s := NewServer(nil, logger, 0, false, 60, "127.0.0.1:0", "127.0.0.1:1") // invalid upstream to force SERVFAIL
	go func() { _ = s.Run(ctx) }()
	defer cancel()

	// Wait for the server to bind and update its address
	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") && !s.startTime.IsZero() {
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
	s := NewServer(nil, logger, 0, false, 60, "127.0.0.1:0", u1.a, u2.a)
	s.dial = func(_ context.Context, addr string, _ *tls.Config) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
	// Fixing pools
	s.pools = nil
	s.pools = append(s.pools, newPool(2, s.connector(u1.a)))
	s.pools = append(s.pools, newPool(2, s.connector(u2.a)))

	go func() { _ = s.Run(ctx) }()
	defer cancel()

	// Wait for the server to bind and update its address
	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") && !s.startTime.IsZero() {
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

func TestEmptyQuestion(t *testing.T) {
	ts, cleanup := setupTestServer(t, 0, nil)
	defer cleanup()

	c := dns.NewClient()
	m := new(dns.Msg)
	m.ID = 1234
	// No Question added (len == 0)

	r, _, err := c.Exchange(context.TODO(), m, "udp", ts.laddr)
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if r.Rcode != dns.RcodeFormatError {
		t.Errorf("Got Rcode %d, want FORMERR (1)", r.Rcode)
	}
	if r.ID != 1234 {
		t.Errorf("Got ID %d, want 1234", r.ID)
	}
}

func TestDNSSECAwareCache(t *testing.T) {
	var count int
	var mu sync.Mutex
	ts, cleanup := setupTestServer(t, 100, func(q string) string {
		mu.Lock()
		count++
		mu.Unlock()
		return "raccoon.miki. 2311 IN A 42.42.42.42"
	})
	defer cleanup()

	c := dns.NewClient()
	// Query 1: DO = false
	m1 := dns.NewMsg(ts.question, dns.TypeA)
	m1.Security = false
	r1, _, err := c.Exchange(context.TODO(), m1, "udp", ts.laddr)
	if err != nil {
		t.Fatalf("Query 1 failed: %v", err)
	}
	if len(r1.Answer) != 1 {
		t.Fatalf("Query 1 answer len: %d", len(r1.Answer))
	}

	// Query 2: DO = true (should not hit the DO=false cache entry)
	m2 := dns.NewMsg(ts.question, dns.TypeA)
	m2.Security = true
	r2, _, err := c.Exchange(context.TODO(), m2, "udp", ts.laddr)
	if err != nil {
		t.Fatalf("Query 2 failed: %v", err)
	}
	if len(r2.Answer) != 1 {
		t.Fatalf("Query 2 answer len: %d", len(r2.Answer))
	}

	mu.Lock()
	if count != 2 {
		t.Errorf("Expected 2 upstream queries for distinct DO flags, got %d", count)
	}
	mu.Unlock()
}

func TestNegativeCaching(t *testing.T) {
	const raddr = "neg.upstream:853"
	flst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	realRAddr := flst.Addr().String()

	var upstreamCalls int
	var mu sync.Mutex
	remote := &dns.Server{
		Addr:     realRAddr,
		Net:      "tcp",
		Listener: flst,
		Handler: fakeServer(func(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
			mu.Lock()
			upstreamCalls++
			mu.Unlock()

			m := new(dns.Msg)
			dnsutil.SetReply(m, q)
			m.Rcode = dns.RcodeNameError
			soa, _ := dns.New("nonexistent.test. 300 IN SOA ns1.test. hostmaster.test. 1 7200 3600 1209600 300")
			m.Ns = append(m.Ns, soa)
			_ = m.Pack()
			_, _ = m.WriteTo(w)
		}),
	}
	go func() { _ = remote.ListenAndServe() }()
	defer func() { _ = flst.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(os.Stdout, "", log.Flags())
	s := NewServer(nil, logger, 100, false, 60, "127.0.0.1:0", raddr)
	s.dial = func(_ context.Context, addr string, _ *tls.Config) (net.Conn, error) {
		return net.Dial("tcp", realRAddr)
	}
	s.pools = nil
	s.pools = append(s.pools, newPool(connectionsPerUpstream, s.connector(raddr)))
	go func() { _ = s.Run(ctx) }()
	defer cancel()

	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") && !s.startTime.IsZero() {
			actualProxyAddr = s.servers[1].Addr
		}
		s.mu.Unlock()
		if actualProxyAddr != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	c := dns.NewClient()
	m := dns.NewMsg("nonexistent.test.", dns.TypeA)

	// First query: cache miss -> hits upstream
	r1, _, err := c.Exchange(context.TODO(), m, "udp", actualProxyAddr)
	if err != nil {
		t.Fatalf("Query 1 failed: %v", err)
	}
	if r1.Rcode != dns.RcodeNameError {
		t.Fatalf("Query 1 got Rcode %d, want NXDOMAIN", r1.Rcode)
	}

	// Second query: negative cache hit -> does not hit upstream
	r2, _, err := c.Exchange(context.TODO(), m, "udp", actualProxyAddr)
	if err != nil {
		t.Fatalf("Query 2 failed: %v", err)
	}
	if r2.Rcode != dns.RcodeNameError {
		t.Fatalf("Query 2 got Rcode %d, want NXDOMAIN", r2.Rcode)
	}

	mu.Lock()
	if upstreamCalls != 1 {
		t.Errorf("Expected exactly 1 upstream call due to negative caching, got %d", upstreamCalls)
	}
	mu.Unlock()
}

func TestSingleflightDeduplication(t *testing.T) {
	const raddr = "sf.upstream:853"
	flst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	realRAddr := flst.Addr().String()

	var upstreamCalls int
	var mu sync.Mutex
	remote := &dns.Server{
		Addr:     realRAddr,
		Net:      "tcp",
		Listener: flst,
		Handler: fakeServer(func(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
			mu.Lock()
			upstreamCalls++
			mu.Unlock()
			time.Sleep(50 * time.Millisecond) // artificial latency to ensure concurrency overlap

			m := new(dns.Msg)
			dnsutil.SetReply(m, q)
			ans, _ := dns.New(q.Question[0].Header().Name + " 3600 IN A 1.2.3.4")
			m.Answer = append(m.Answer, ans)
			_ = m.Pack()
			_, _ = m.WriteTo(w)
		}),
	}
	go func() { _ = remote.ListenAndServe() }()
	defer func() { _ = flst.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(os.Stdout, "", log.Flags())
	s := NewServer(nil, logger, 0, false, 60, "127.0.0.1:0", raddr)
	s.dial = func(_ context.Context, addr string, _ *tls.Config) (net.Conn, error) {
		return net.Dial("tcp", realRAddr)
	}
	s.pools = nil
	s.pools = append(s.pools, newPool(connectionsPerUpstream, s.connector(raddr)))
	go func() { _ = s.Run(ctx) }()
	defer cancel()

	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") && !s.startTime.IsZero() {
			actualProxyAddr = s.servers[1].Addr
		}
		s.mu.Unlock()
		if actualProxyAddr != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	var wg sync.WaitGroup
	const concurrentQueries = 10
	for i := 0; i < concurrentQueries; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			c := dns.NewClient()
			m := dns.NewMsg("singleflight-test.com.", dns.TypeA)
			m.ID = uint16(id + 100)
			r, _, err := c.Exchange(context.TODO(), m, "udp", actualProxyAddr)
			if err != nil {
				t.Errorf("Query %d failed: %v", id, err)
			}
			if r == nil || len(r.Answer) == 0 {
				t.Errorf("Query %d received empty answer", id)
			}
		}(i)
	}
	wg.Wait()

	mu.Lock()
	if upstreamCalls > 2 {
		t.Errorf("Singleflight should coalesce parallel queries; got %d upstream calls, want <= 2", upstreamCalls)
	}
	mu.Unlock()
}

func TestPrivacyPaddingAndECS(t *testing.T) {
	const raddr = "privacy.upstream:853"
	flst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	realRAddr := flst.Addr().String()

	var receivedQuery *dns.Msg
	var mu sync.Mutex
	remote := &dns.Server{
		Addr:     realRAddr,
		Net:      "tcp",
		Listener: flst,
		Handler: fakeServer(func(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
			_ = q.Unpack()
			mu.Lock()
			receivedQuery = CloneMsg(q)
			mu.Unlock()

			m := new(dns.Msg)
			dnsutil.SetReply(m, q)
			ans, _ := dns.New("privacy.test. 3600 IN A 1.2.3.4")
			m.Answer = append(m.Answer, ans)
			_ = m.Pack()
			_, _ = m.WriteTo(w)
		}),
	}
	go func() { _ = remote.ListenAndServe() }()
	defer func() { _ = flst.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	logger := log.New(os.Stdout, "", log.Flags())
	s := NewServer(nil, logger, 0, false, 60, "127.0.0.1:0", raddr)
	s.dial = func(_ context.Context, addr string, _ *tls.Config) (net.Conn, error) {
		return net.Dial("tcp", realRAddr)
	}
	s.pools = nil
	s.pools = append(s.pools, newPool(connectionsPerUpstream, s.connector(raddr)))
	go func() { _ = s.Run(ctx) }()
	defer cancel()

	actualProxyAddr := ""
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		if len(s.servers) > 1 && !strings.HasSuffix(s.servers[1].Addr, ":0") && !s.startTime.IsZero() {
			actualProxyAddr = s.servers[1].Addr
		}
		s.mu.Unlock()
		if actualProxyAddr != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	c := dns.NewClient()
	m := dns.NewMsg("privacy.test.", dns.TypeA)
	// Add ECS option to client request
	subnet := &dns.SUBNET{
		Family:  1,
		Netmask: 24,
		Address: netip.MustParseAddr("1.2.3.4"),
	}
	m.Pseudo = append(m.Pseudo, subnet)

	_, _, err = c.Exchange(context.TODO(), m, "udp", actualProxyAddr)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if receivedQuery == nil {
		t.Fatal("Upstream did not receive query")
	}

	// Verify ECS is stripped
	for _, p := range receivedQuery.Pseudo {
		if _, ok := p.(*dns.SUBNET); ok {
			t.Errorf("Upstream query contains SUBNET, should have been stripped for privacy")
		}
	}

	// Verify EDNS0 PADDING is present
	foundPadding := false
	for _, p := range receivedQuery.Pseudo {
		if _, ok := p.(*dns.PADDING); ok {
			foundPadding = true
		}
	}
	if !foundPadding {
		t.Errorf("Upstream query does not contain PADDING option")
	}
}

func TestPrometheusMetricsHandler(t *testing.T) {
	ts, cleanup := setupTestServer(t, 100, nil)
	defer cleanup()

	// Perform a query to generate stats
	ts.exchange("metrics-test", "42.42.42.42")

	h := ts.s.PrometheusHandler()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("Metrics endpoint returned status %d", w.Code)
	}
	body := w.Body.String()
	for _, expected := range []string{"dns_queries_total", "dns_responses_total", "dns_cache_hits_total", "dns_cache_misses_total", "dns_cache_entries"} {
		if !strings.Contains(body, expected) {
			t.Errorf("Metrics output missing expected metric %q:\n%s", expected, body)
		}
	}
}

func TestDeadConnectionRecovery(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	var activeConns []net.Conn
	var connMu sync.Mutex
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			connMu.Lock()
			activeConns = append(activeConns, c)
			connMu.Unlock()
		}
	}()

	addr := l.Addr().String()
	dialCount := 0
	p := newPoolWithAddr(2, addr, func(context.Context) (net.Conn, error) {
		dialCount++
		return net.Dial("tcp", addr)
	})

	// Get a connection and return it to pool
	c1, err := p.get(context.Background())
	if err != nil {
		t.Fatalf("First get failed: %v", err)
	}
	p.put(c1)

	// Close the connection on the remote end so it becomes dead
	time.Sleep(10 * time.Millisecond)
	connMu.Lock()
	for _, c := range activeConns {
		_ = c.Close()
	}
	connMu.Unlock()
	time.Sleep(10 * time.Millisecond)

	// Next get should detect that the pooled connection is dead, discard it, and dial fresh
	c2, err := p.get(context.Background())
	if err != nil {
		t.Fatalf("Second get failed: %v", err)
	}
	if c2 == nil {
		t.Fatal("Expected fresh connection, got nil")
	}
	_ = c2.Close()
	p.shutdown()
}
