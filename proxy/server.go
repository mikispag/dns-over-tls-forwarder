package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/gologme/log"
	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
	"golang.org/x/sync/errgroup"
)

const (
	defaultCacheSize       = 65536
	connectionTimeout      = 10 * time.Second
	connectionsPerUpstream = 2
	refreshQueueSize       = 2048
	timerResolution        = 1 * time.Second
)

// Server is a caching DNS proxy that upgrades DNS to DNS over TLS.
type Server struct {
	servers []*dns.Server
	cache   *cache
	pools   []*pool
	rq      chan *dns.Msg
	dial    func(addr string, cfg *tls.Config) (net.Conn, error)
	minTTL  int

	mu          sync.RWMutex
	currentTime time.Time
	startTime   time.Time
	Log         *log.Logger
}

// NewServer constructs a new server but does not start it, use Run to start it afterwards.
// Calling New(0) is valid and comes with working defaults:
// * If cacheSize is 0 a default value will be used. to disable caches use a negative value.
// * If no upstream servers are specified default ones will be used.
func NewServer(mux *dns.ServeMux, log *log.Logger, cacheSize int, evictMetrics bool, minTTL int, addr string, upstreamServers ...string) *Server {
	switch {
	case cacheSize == 0:
		cacheSize = defaultCacheSize
	case cacheSize < 0:
		cacheSize = 0
	}
	cache, err := newCache(cacheSize, evictMetrics)
	if err != nil {
		log.Fatal("Unable to initialize the cache")
	}
	s := &Server{
		servers: []*dns.Server{
			{Addr: addr, Net: "tcp", Handler: mux, ReusePort: true},
			{Addr: addr, Net: "udp", Handler: mux, ReusePort: true},
		},
		cache: cache,
		rq:    make(chan *dns.Msg, refreshQueueSize),
		dial: func(addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.Dial("tcp", addr, cfg)
		},
		minTTL: minTTL,
		Log:    log,
	}
	if len(upstreamServers) == 0 {
		upstreamServers = []string{"one.one.one.one:853@1.1.1.1", "dns.google:853@8.8.8.8"}
		s.Log.Infof("No DNS over TLS server addresses provided. Used default servers.")
	}
	for _, addr := range upstreamServers {
		s.Log.Infof("DNS over TLS address: %v", addr)
		s.pools = append(s.pools, newPool(connectionsPerUpstream, s.connector(addr)))
	}
	s.Log.Infof("DNS over TLS forwarder listening on %v", addr)
	return s
}

func (s *Server) connector(upstreamServer string) func() (net.Conn, error) {
	return func() (net.Conn, error) {
		tlsConf := &tls.Config{
			// Force TLS 1.3 as minimum version.
			MinVersion: tls.VersionTLS13,
		}
		dialableAddress := upstreamServer
		serverComponents := strings.Split(upstreamServer, "@")
		if len(serverComponents) == 2 {
			servername, port, err := net.SplitHostPort(serverComponents[0])
			if err != nil {
				s.Log.Warnf("Failed to parse DNS-over-TLS upstream address: %v", err)
				return nil, err
			}
			tlsConf.ServerName = servername
			dialableAddress = serverComponents[1] + ":" + port
		}
		conn, err := s.dial(dialableAddress, tlsConf)
		if err != nil {
			s.Log.Warnf("Failed to connect to DNS-over-TLS upstream: %v", err)
			return nil, err
		}
		return conn, nil
	}
}

// Run runs the server. The server will gracefully shutdown when context is canceled.
func (s *Server) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	go s.refresher(ctx)
	go s.timer(ctx)

	// We use a WaitGroup to ensure servers have started before we allow Shutdown to be called.
	// This avoids internal data races in the library between starting and stopping.
	var startWg sync.WaitGroup
	startWg.Add(len(s.servers))

	for _, srv := range s.servers {
		srv := srv
		// NotifyStartedFunc is called by the library once the server is listening.
		srv.NotifyStartedFunc = func(ctx context.Context) {
			startWg.Done()
		}

		// Pre-listen to avoid internal library data races on the Listener/PacketConn fields.
		if srv.Net == "tcp" || srv.Net == "tcp-tls" {
			if srv.Listener == nil {
				l, err := net.Listen("tcp", srv.Addr)
				if err != nil {
					return err
				}
				srv.Listener = l
			}
			s.mu.Lock()
			srv.Addr = srv.Listener.Addr().String()
			s.mu.Unlock()
		} else if srv.Net == "udp" {
			if srv.PacketConn == nil {
				pc, err := net.ListenPacket("udp", srv.Addr)
				if err != nil {
					return err
				}
				srv.PacketConn = pc
			}
			s.mu.Lock()
			srv.Addr = srv.PacketConn.LocalAddr().String()
			s.mu.Unlock()
		}

		g.Go(func() error { return srv.ListenAndServe() })
	}

	// Capture the startWg so we can wait for it safely.
	started := make(chan struct{})
	go func() {
		startWg.Wait()
		close(started)
	}()

	// Gracefully shutdown when context is canceled.
	go func() {
		<-ctx.Done()
		// Wait for all servers to have finished their startup sequence.
		select {
		case <-started:
			// Additional safety delay for internal library state stabilization.
			time.Sleep(500 * time.Millisecond)
		case <-time.After(5 * time.Second):
		}
		_ = s.Shutdown(context.Background())
	}()

	s.mu.Lock()
	s.startTime = time.Now()
	s.mu.Unlock()
	err := g.Wait()
	for _, p := range s.pools {
		p.shutdown()
	}
	return err
}

// Shutdown DNS server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, srv := range s.servers {
		srv.Shutdown(ctx)
	}
	for _, p := range s.pools {
		p.shutdown()
	}
	return ctx.Err()
}

// ServeDNS implements miekg/dns.Handler for Server.
func (s *Server) ServeDNS(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
	// Ensure the message is fully unpacked (especially the Extra/Pseudo sections for EDNS).
	_ = q.Unpack()
	inboundIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	s.Log.Debugf("Question from %s: %s", inboundIP, q.String())
	m := s.GetAnswer(ctx, q)
	if m == nil {
		// Build a SERVFAIL response.
		m = new(dns.Msg)
		dnsutil.SetReply(m, q)
		m.Rcode = dns.RcodeServerFailure
		// Propagate EDNS settings from query if present.
		m.UDPSize = q.UDPSize
		m.Security = q.Security
	} else {
		// Ensure the response ID matches the question ID.
		m.ID = q.ID
		// Ensure EDNS settings are compatible with client's request if we have a response.
		// Cloudflare/Upstream might have returned a smaller UDPSize than client requested,
		// which is fine. But if client requested DO bit, we should ensure it's there if upstream returned it.
	}

	s.Log.Debugf("Answer to %s: %s", inboundIP, m.String())
	_ = m.Pack()
	if _, err := m.WriteTo(w); err != nil {
		s.Log.Warnf("Write message failed, message: %v, error: %v", m, err)
	}
}

type debugStats struct {
	CacheMetrics       specialized.CacheMetrics
	CacheLen, CacheCap int
	Uptime             string
}

// DebugHandler returns an http.Handler that serves debug stats.
func (s *Server) DebugHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s.mu.Lock()
		uptime := time.Since(s.startTime).String()
		s.mu.Unlock()
		buf, err := json.MarshalIndent(debugStats{
			s.cache.c.Metrics(),
			s.cache.c.Len(),
			s.cache.c.Cap(),
			uptime,
		}, "", " ")
		if err != nil {
			http.Error(w, "Unable to retrieve debug info", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(buf)
	})
}

func (s *Server) GetAnswer(ctx context.Context, q *dns.Msg) *dns.Msg {
	m, ok := s.cache.get(q)
	// Cache HIT.
	if ok {
		return m
	}
	// If there is a cache HIT with an expired TTL, speculatively return the cache entry anyway with a short TTL, and refresh it.
	if !ok && m != nil {
		s.refresh(q)
		return m
	}
	// If there is a cache MISS, forward the message upstream (with TTL rewritten) and return the answer.
	return s.forwardMessageAndCacheResponse(ctx, q)
}

func (s *Server) refresh(q *dns.Msg) {
	select {
	case s.rq <- CloneMsg(q):
	default:
	}
}

func (s *Server) refresher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-s.rq:
			s.forwardMessageAndCacheResponse(ctx, q)
		}
	}
}

func (s *Server) timer(ctx context.Context) {
	t := time.NewTicker(timerResolution)
	for {
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case t := <-t.C:
			s.mu.Lock()
			s.currentTime = t
			s.mu.Unlock()
		}
	}
}

func (s *Server) forwardMessageAndCacheResponse(ctx context.Context, q *dns.Msg) (m *dns.Msg) {
	m = s.forwardMessageAndGetResponse(ctx, q)
	// Let's retry a few times if we can't resolve it at the first try.
	for c := 0; m == nil && c < connectionsPerUpstream; c++ {
		s.Log.Debugf("Retrying %q [%d/%d]...", q.Question, c+1, connectionsPerUpstream)
		m = s.forwardMessageAndGetResponse(ctx, q)
	}
	if m == nil {
		s.Log.Infof("Giving up on %q after %d connection retries.", q.Question, connectionsPerUpstream)
		return nil
	}
	if m.Answer != nil {
		// Rewrite the TTL.
		for _, a := range m.Answer {
			// If the TTL provided upstream is smaller than `minTTL`, rewrite it.
			a.Header().TTL = uint32(max(a.Header().TTL, uint32(s.minTTL)))
		}
	}
	s.cache.put(q, m)
	return m
}

func (s *Server) forwardMessageAndGetResponse(ctx context.Context, q *dns.Msg) (m *dns.Msg) {
	resps := make(chan *dns.Msg, len(s.pools))
	for _, p := range s.pools {
		go func(p *pool) {
			// Clone q for each goroutine to avoid data races during Pack().
			qc := CloneMsg(q)
			// Ensure we don't send the Data buffer if it was already packed for a different upstream.
			qc.Data = nil
			r, _ := s.exchangeMessages(ctx, p, qc)
			resps <- r
		}(p)
	}

	var bestErrResp *dns.Msg
	for c := 0; c < len(s.pools); c++ {
		r := <-resps
		if r == nil {
			continue
		}
		// Return the response immediately if it has Rcode NoError or NXDomain.
		if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
			return r
		}
		// Keep track of the first valid error response we get to return it later as fallback
		if bestErrResp == nil {
			bestErrResp = r
		}
	}
	// Return the error response (like SERVFAIL with EDE payload) if no NOERROR was found.
	return bestErrResp
}

var errNilResponse = errors.New("nil response from upstream")

func (s *Server) exchangeMessages(ctx context.Context, p *pool, q *dns.Msg) (resp *dns.Msg, err error) {
	c, err := p.get()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err == nil {
			p.put(c)
		}
	}()
	client := dns.NewClient()
	resp, _, err = client.ExchangeWithConn(ctx, q, c)
	if err != nil {
		s.Log.Debugf("Exchange failed: %v", err)
		_ = c.Close()
		return nil, err
	}
	if resp == nil {
		s.Log.Debug(errNilResponse)
		_ = c.Close()
		return nil, errNilResponse
	}
	return resp, err
}
