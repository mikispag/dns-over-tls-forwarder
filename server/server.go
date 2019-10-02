package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/mikispag/dns-over-tls-forwarder/cache"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	cacheSize         = 65536
	connectionTimeout = 10 * time.Second
	refreshQueueSize  = 2048
)

type Server struct {
	cache          *cache.Cache
	cloudFlarePool *pool
	googlePool     *pool
	rq             chan *dns.Msg
}

func New() *Server {
	return &Server{
		cache: cache.New(cacheSize),
		cloudFlarePool: newPool(5, func() (*dns.Conn, error) {
			c, err := connectToUpstream("one.one.one.one:853@1.1.1.1")
			if err != nil {
				return nil, fmt.Errorf("Unable to connect to CloudFlare upstream: %v", err)
			}
			return &dns.Conn{Conn: c}, nil
		}),
		googlePool: newPool(5, func() (*dns.Conn, error) {
			c, err := connectToUpstream("dns.google:853@8.8.8.8")
			if err != nil {
				return nil, fmt.Errorf("Unable to connect to Google upstream: %v", err)
			}
			return &dns.Conn{Conn: c}, nil
		}),
		rq: make(chan *dns.Msg, refreshQueueSize),
	}
}

func connectToUpstream(upstreamServer string) (net.Conn, error) {
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
	conn, err := tls.Dial("tcp", dialableAddress, &tlsConf)
	if err != nil {
		log.Warnf("Failed to connect to DNS-over-TLS upstream: %v", err)
		return nil, err
	}
	return conn, nil
}

func exchangeMessages(c *dns.Conn, q *dns.Msg, out chan *dns.Msg) {
	if err := c.WriteMsg(q); err != nil {
		log.Debugf("Send question message failed: %v", err)
		out <- nil
	}
	m, err := c.ReadMsg()
	if err != nil {
		log.Debugf("Error while reading message: %v", err)
		out <- nil
	}
	if m == nil {
		log.Debug("Response message returned nil. Please check your query or DNS configuration")
		out <- nil
	}
	out <- m
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
		s.cloudFlarePool.shutdown()
		s.googlePool.shutdown()
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
	cloudFlareConn, errCloudFlare := s.cloudFlarePool.get()
	if errCloudFlare != nil {
		cloudFlareConn.Close()
	} else {
		cloudFlareConn.SetDeadline(time.Now().Add(connectionTimeout))
	}
	googleConn, errGoogle := s.googlePool.get()
	if errGoogle != nil {
		googleConn.Close()
		if errCloudFlare != nil {
			return nil
		}
	} else {
		googleConn.SetDeadline(time.Now().Add(connectionTimeout))
	}
	defer func() {
		if m == nil {
			cloudFlareConn.Close()
			googleConn.Close()
			return
		}
		if errCloudFlare != nil {
			cloudFlareConn.Close()
		} else {
			s.cloudFlarePool.put(cloudFlareConn)
		}
		if errGoogle != nil {
			googleConn.Close()
		} else {
			s.googlePool.put(googleConn)
		}
	}()

	// Race between CloudFlare and Google upstream servers.
	msgChan := make(chan *dns.Msg, 2)
	go exchangeMessages(cloudFlareConn, q, msgChan)
	go exchangeMessages(googleConn, q, msgChan)

	m = <-msgChan
	if m != nil {
		return m
	}
	return <-msgChan
}
