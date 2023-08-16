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

	"github.com/miekg/dns"
	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
	log "github.com/sirupsen/logrus"
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
	cache *cache
	pools []*pool
	rq    chan *dns.Msg
	dial  func(addr string, cfg *tls.Config) (net.Conn, error)

	mu          sync.RWMutex
	currentTime time.Time
	startTime   time.Time
}

// NewServer constructs a new server but does not start it, use Run to start it afterwards.
// Calling New(0) is valid and comes with working defaults:
// * If cacheSize is 0 a default value will be used. to disable caches use a negative value.
// * If no upstream servers are specified default ones will be used.
func NewServer(cacheSize int, evictMetrics bool, upstreamServers ...string) *Server {
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
		cache: cache,
		rq:    make(chan *dns.Msg, refreshQueueSize),
		dial: func(addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.Dial("tcp", addr, cfg)
		},
	}
	if len(upstreamServers) == 0 {
		s.pools = []*pool{
			newPool(connectionsPerUpstream, s.connector("one.one.one.one:853@1.1.1.1")),
			newPool(connectionsPerUpstream, s.connector("dns.google:853@8.8.8.8")),
		}
	} else {
		for _, addr := range upstreamServers {
			s.pools = append(s.pools, newPool(connectionsPerUpstream, s.connector(addr)))
		}
	}
	return s
}

func (s *Server) connector(upstreamServer string) func() (*dns.Conn, error) {
	return func() (*dns.Conn, error) {
		tlsConf := &tls.Config{
			// Force TLS 1.2 as minimum version.
			MinVersion: tls.VersionTLS13,
		}
		dialableAddress := upstreamServer
		serverComponents := strings.Split(upstreamServer, "@")
		if len(serverComponents) == 2 {
			servername, port, err := net.SplitHostPort(serverComponents[0])
			if err != nil {
				log.Warnf("Failed to parse DNS-over-TLS upstream address: %v", err)
				return nil, err
			}
			tlsConf.ServerName = servername
			dialableAddress = serverComponents[1] + ":" + port
		}
		conn, err := s.dial(dialableAddress, tlsConf)
		if err != nil {
			log.Warnf("Failed to connect to DNS-over-TLS upstream: %v", err)
			return nil, err
		}
		return &dns.Conn{Conn: conn}, nil
	}
}

// Run runs the server. The server will gracefully shutdown when context is canceled.
func (s *Server) RunWithHandle(ctx context.Context, addr string, handler func(dns.ResponseWriter, *dns.Msg)) error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", handler)

	servers := []*dns.Server{
		{Addr: addr, Net: "tcp", Handler: mux, ReusePort: false},
		//{Addr: addr, Net: "udp", Handler: mux, ReusePort: false},
	}

	g, ctx := errgroup.WithContext(ctx)

	go func() {
		<-ctx.Done()
		for _, s := range servers {
			_ = s.Shutdown()
		}
		for _, p := range s.pools {
			p.shutdown()
		}
	}()

	go s.refresher(ctx)
	go s.timer(ctx)

	for _, s := range servers {
		s := s
		g.Go(func() error { return s.ListenAndServe() })
	}

	s.startTime = time.Now()
	log.Infof("DNS over TLS forwarder listening on %v", addr)
	return g.Wait()
}

// ServeDNS implements miekg/dns.Handler for Server.
func (s *Server) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	inboundIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	log.Debugf("Question from %s: %q", inboundIP, q.Question[0])
	m := s.GetAnswer(q)
	if m == nil {
		dns.HandleFailed(w, q)
		return
	}
	if err := w.WriteMsg(m); err != nil {
		log.Warnf("Write message failed, message: %v, error: %v", m, err)
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
		buf, err := json.MarshalIndent(debugStats{
			s.cache.c.Metrics(),
			s.cache.c.Len(),
			s.cache.c.Cap(),
			time.Since(s.startTime).String(),
		}, "", " ")
		if err != nil {
			http.Error(w, "Unable to retrieve debug info", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(buf)
	})
}

func (s *Server) GetAnswer(q *dns.Msg) *dns.Msg {
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
	// If there is a cache MISS, forward the message upstream and return the answer.
	// miek/dns does not pass a context so we fallback to Background.
	return s.forwardMessageAndCacheResponse(q)
}

func (s *Server) refresh(q *dns.Msg) {
	select {
	case s.rq <- q:
	default:
	}
}

func (s *Server) refresher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-s.rq:
			s.forwardMessageAndCacheResponse(q)
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

func (s *Server) now() time.Time {
	s.mu.RLock()
	t := s.currentTime
	s.mu.RUnlock()
	return t
}

func (s *Server) forwardMessageAndCacheResponse(q *dns.Msg) (m *dns.Msg) {
	m = s.forwardMessageAndGetResponse(q)
	// Let's retry a few times if we can't resolve it at the first try.
	for c := 0; m == nil && c < connectionsPerUpstream; c++ {
		log.Debugf("Retrying %q [%d/%d]...", q.Question, c+1, connectionsPerUpstream)
		m = s.forwardMessageAndGetResponse(q)
	}
	if m == nil {
		log.Infof("Giving up on %q after %d connection retries.", q.Question, connectionsPerUpstream)
		return nil
	}
	s.cache.put(q, m)
	return m
}

func (s *Server) forwardMessageAndGetResponse(q *dns.Msg) (m *dns.Msg) {
	resps := make(chan *dns.Msg, len(s.pools))
	for _, p := range s.pools {
		go func(p *pool) {
			r, err := s.exchangeMessages(p, q)
			if err != nil || r == nil {
				resps <- nil
			}
			resps <- r
		}(p)
	}
	for c := 0; c < len(s.pools); c++ {
		r := <-resps
		// Return the response only if it has Rcode NoError or NXDomain, otherwise try another pool.
		if r != nil && (r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError) {
			return r
		}
	}
	return nil
}

var errNilResponse = errors.New("nil response from upstream")

func (s *Server) exchangeMessages(p *pool, q *dns.Msg) (resp *dns.Msg, err error) {
	c, err := p.get()
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(s.now().Add(connectionTimeout))
	defer func() {
		if err == nil {
			p.put(c)
		}
	}()
	if err := c.WriteMsg(q); err != nil {
		log.Debugf("Send question message failed: %v", err)
		c.Close()
		return nil, err
	}
	resp, err = c.ReadMsg()
	if err != nil {
		log.Debugf("Error while reading message: %v", err)
		c.Close()
		return nil, err
	}
	if resp == nil {
		log.Debug(errNilResponse)
		c.Close()
		return nil, errNilResponse
	}
	return resp, err
}
