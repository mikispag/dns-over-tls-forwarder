package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/mikispag/dns-over-tls-forwarder/cache"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	cacheSize        = 65536
	refreshQueueSize = 2048
)

type Server struct {
	upstreamServer string
	cache          *cache.Cache
	p              *pool
	rq             chan *dns.Msg
}

func New(upstreamServer string) *Server {
	s := &Server{
		upstreamServer: upstreamServer,
		cache:          cache.New(cacheSize),
	}
	s.p = newPool(5, func() (*dns.Conn, error) {
		c, err := s.connectToUpstream()
		if err != nil {
			return nil, fmt.Errorf("unable to connect to upstream: %v", err)
		}
		return &dns.Conn{Conn: c, UDPSize: 65535}, nil
	})
	return s
}

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
		s.p.shutdown()
	}()

	s.rq = make(chan *dns.Msg, refreshQueueSize)
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

func (s *Server) forwardMessageAndCacheResponse(q *dns.Msg) (m *dns.Msg) {
	m = s.forwardMessageAndGetResponse(q)
	// Let's try a couple of times if we can't resolve it at the first try.
	for c := 0; m == nil && c < 2; c++ {
		m = s.forwardMessageAndGetResponse(q)
	}
	if m == nil {
		return nil
	}
	s.cache.Put(q, m)
	return m
}

func (s *Server) forwardMessageAndGetResponse(q *dns.Msg) (m *dns.Msg) {
	c, err := s.p.get()
	if err != nil {
		return nil
	}
	defer func() {
		if m == nil {
			c.Close()
			return
		}
		s.p.put(c)
	}()

	if err := c.WriteMsg(q); err != nil {
		log.Warnf("Send question message failed: %v", err)
		return nil
	}
	m, err = c.ReadMsg()
	if err != nil {
		log.Debugf("Error while reading message: %v", err)
		return nil
	}
	if m == nil {
		log.Debug("Response message returned nil. Please check your query or DNS configuration")
		return nil
	}
	return m
}

func (s *Server) connectToUpstream() (net.Conn, error) {
	var tlsConf tls.Config
	dialableAddress := s.upstreamServer
	serverComponents := strings.Split(s.upstreamServer, "@")
	if len(serverComponents) == 2 {
		servername, port, err := net.SplitHostPort(serverComponents[0])
		if err != nil {
			log.Warnf("Failed to parse DNS-over-TLS upstream address: %v", err)
			return nil, err
		}
		tlsConf.ServerName = servername
		dialableAddress = serverComponents[1] + ":" + port
	}
	conn, err := tls.Dial("tcp", dialableAddress, &tlsConf)
	if err != nil {
		log.Warnf("Failed to connect to DNS-over-TLS upstream: %v", err)
		return nil, err
	}
	return conn, nil
}
