package server

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mikispag/dns-over-tls-forwarder/cache"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	defaultCacheSize  = 65536
	connectionTimeout = 10 * time.Second
	refreshQueueSize  = 2048
)

type Server struct {
	cache *cache.Cache
	pools []*pool
	rq    chan *dns.Msg
	dial  func(addr string, cfg *tls.Config) (net.Conn, error)
}

// New constructs a new server but does not start it, use Run to start it afterwards.
// * If cacheSize is 0 a default cache size will be used. To disable caches use a negative value.
// * The list of upstream servers is mandatory.
func New(cacheSize int, upstreamServers ...string) *Server {
	switch {
	case cacheSize == 0:
		cacheSize = defaultCacheSize
	case cacheSize < 0:
		cacheSize = 0
	}
	s := &Server{
		cache: cache.New(cacheSize),
		rq:    make(chan *dns.Msg, refreshQueueSize),
		dial: func(addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.Dial("tcp", addr, cfg)
		},
	}
	if len(upstreamServers) == 0 {
		log.Fatal("No upstream servers specified.")
	} else {
		for _, addr := range upstreamServers {
			s.pools = append(s.pools, newPool(5, s.connector(addr)))
		}
	}
	return s
}

func (s *Server) connector(upstreamServer string) func() (*dns.Conn, error) {
	return func() (*dns.Conn, error) {
		var tlsConf tls.Config
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
		conn, err := s.dial(dialableAddress, &tlsConf)
		if err != nil {
			log.Warnf("Failed to connect to DNS-over-TLS upstream: %v", err)
			return nil, err
		}
		return &dns.Conn{Conn: conn}, nil
	}
}

// Run runs the server. The server will gracefully shutdown when context is canceled.
func (s *Server) Run(ctx context.Context, addr string) error {
	mux := dns.NewServeMux()
	mux.Handle(".", s)

	servers := []dns.Server{
		{Addr: addr, Net: "tcp", Handler: mux},
		{Addr: addr, Net: "udp", Handler: mux},
	}

	g, ctx := errgroup.WithContext(ctx)

	go func() {
		<-ctx.Done()
		for _, s := range servers {
			s.Shutdown()
		}
		for _, p := range s.pools {
			p.shutdown()
		}
	}()

	go s.refresher(ctx)

	for _, s := range servers {
		s := s
		g.Go(func() error { return s.ListenAndServe() })
	}

	return g.Wait()
}

func (s *Server) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	inboundIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())
	log.Debugf("Question from %s: %q", inboundIP, q.Question[0])
	m := s.getAnswer(q)
	if m == nil {
		dns.HandleFailed(w, q)
		return
	}
	if err := w.WriteMsg(m); err != nil {
		log.Warnf("Write message failed, message: %v, error: %v", m, err)
	}
}

func (s *Server) getAnswer(q *dns.Msg) *dns.Msg {
	m, ok := s.cache.Get(q)
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
	return s.forwardMessageAndCacheResponse(context.Background(), q)
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
			s.forwardMessageAndCacheResponse(ctx, q)
		}
	}
}

func (s *Server) forwardMessageAndCacheResponse(ctx context.Context, q *dns.Msg) (m *dns.Msg) {
	m = s.forwardMessageAndGetResponse(ctx, q)
	// Let's try a couple of times if we can't resolve it at the first try.
	for c := 0; m == nil && c < 2; c++ {
		m = s.forwardMessageAndGetResponse(ctx, q)
	}
	if m == nil {
		return nil
	}
	s.cache.Put(q, m)
	return m
}

func (s *Server) forwardMessageAndGetResponse(ctx context.Context, q *dns.Msg) (m *dns.Msg) {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(connectionTimeout))
	// This causes all concurrent connections to terminate early if we have a response already.
	defer cancel()
	resps := make(chan *dns.Msg, len(s.pools))
	for _, p := range s.pools {
		go func(p *pool) {
			r, err := exchangeMessages(ctx, p, q)
			if err != nil || r == nil {
				resps <- nil
			}
			resps <- r
		}(p)
	}
	for c := 0; c < len(s.pools); c++ {
		if r := <-resps; r != nil {
			return r
		}
	}
	return nil
}

func exchangeMessages(ctx context.Context, p *pool, q *dns.Msg) (resp *dns.Msg, err error) {
	c, err := p.get()
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(connectionTimeout))
	defer func() {
		if resp == nil || err != nil {
			c.Close()
			return
		}
		p.put(c)
	}()
	go func() {
		<-ctx.Done()
		// Our work is not needed anymore, abort all I/O.
		c.SetDeadline(time.Now())
	}()
	if err := c.WriteMsg(q); err != nil {
		log.Debugf("Send question message failed: %v", err)
		return nil, err
	}
	resp, err = c.ReadMsg()
	if err != nil {
		log.Debugf("Error while reading message: %v", err)
		return nil, err
	}
	if resp == nil {
		log.Debug("Response message returned nil. Please check your query or DNS configuration")
		return nil, err
	}
	return resp, err
}
