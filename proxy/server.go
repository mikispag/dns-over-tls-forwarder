package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/gologme/log"
	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

const (
	defaultCacheSize       = 65536
	connectionTimeout      = 10 * time.Second
	exchangeWriteTimeout   = 2 * time.Second
	connectionsPerUpstream = 2
	refreshQueueSize       = 2048
	// lookupAttempts bounds rounds in which no upstream responds. A resolver
	// that timed out on a slow name usually has it cached by the next round.
	lookupAttempts = 3
	// maxPendingLookups bounds upstream lookups in flight; further cache
	// misses fail immediately with SERVFAIL.
	maxPendingLookups = 1024
	// ednsPayloadSize is the advertised EDNS UDP payload size and the largest
	// UDP reply (DNS Flag Day 2020).
	ednsPayloadSize = 1232
)

// Server is a caching DNS proxy that upgrades DNS to DNS over TLS.
type Server struct {
	servers []*dns.Server
	cache   *cache
	pools   []*pool
	rq      chan *dns.Msg
	lookups chan struct{} // slots for pending upstream lookups
	dial    func(context.Context, string, *tls.Config) (net.Conn, error)
	minTTL  int

	sf      singleflight.Group
	metrics *ServerMetrics

	refreshMu      sync.Mutex
	refreshPending map[string]struct{}

	mu         sync.RWMutex
	workers    sync.WaitGroup
	stopping   bool
	runContext context.Context
	cancel     context.CancelFunc
	done       chan struct{}
	initErr    error
	startTime  time.Time
	Log        *log.Logger
}

// NewServer constructs a new server but does not start it, use Run to start it afterwards.
// A nil mux forwards every query; a supplied mux controls query routing.
// A zero cacheSize selects the default capacity; a negative size disables caching.
// Without upstreamServers, the Cloudflare and Google defaults are used.
// Configuration errors are returned by Run. A nil logger discards output.
func NewServer(mux *dns.ServeMux, logger *log.Logger, cacheSize int, evictMetrics bool, minTTL int, addr string, upstreamServers ...string) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	switch {
	case cacheSize == 0:
		cacheSize = defaultCacheSize
	case cacheSize < 0:
		cacheSize = 0
	}
	cache, err := newCache(cacheSize, evictMetrics)

	s := &Server{
		servers: []*dns.Server{
			{Addr: addr, Net: "tcp", Handler: mux},
			// The default 1400-byte read buffer fits any realistic query. The
			// library allocates it per packet and never reclaims it here,
			// because replies are written from a new message.
			{Addr: addr, Net: "udp", Handler: mux},
		},
		cache:   cache,
		rq:      make(chan *dns.Msg, refreshQueueSize),
		lookups: make(chan struct{}, maxPendingLookups),
		dial: func(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
			dialer := tls.Dialer{Config: cfg}
			return dialer.DialContext(ctx, "tcp", addr)
		},
		minTTL:         max(0, minTTL),
		initErr:        err,
		refreshPending: make(map[string]struct{}),
		metrics:        newServerMetrics(),
		Log:            logger,
	}
	if mux == nil {
		for _, listener := range s.servers {
			listener.Handler = s
			listener.MsgAcceptFunc = acceptRequest
		}
	}
	if len(upstreamServers) == 0 {
		upstreamServers = []string{"one.one.one.one:853@1.1.1.1", "dns.google:853@8.8.8.8"}
		s.Log.Infof("No DNS over TLS server addresses provided. Used default servers.")
	}
	s.initErr = errors.Join(s.initErr, ValidateUpstreams(upstreamServers...), validateListenAddress(addr, runtime.GOOS))
	for _, addr := range upstreamServers {
		s.Log.Infof("DNS over TLS address: %v", addr)
		s.pools = append(s.pools, newPoolWithAddr(connectionsPerUpstream, addr, s.connector(addr)))
	}
	return s
}

// The DNS dependency cannot preserve UDP destination addresses on Windows.
func validateListenAddress(addr, goos string) error {
	if goos != "windows" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if host == "" || (ip != nil && ip.IsUnspecified()) {
		return errors.New("wildcard listening is unsupported on Windows; bind to an explicit local IP address")
	}
	return nil
}

// acceptRequest passes every request to ServeDNS, which answers malformed and
// unsupported ones itself and counts them. The DNS library's default policy
// refuses RRSIG queries, which a forwarder must pass on, and answers some
// errors before the handler sees them. Responses are dropped to avoid loops.
func acceptRequest(m *dns.Msg) dns.MsgAcceptAction {
	if m.Response {
		return dns.MsgIgnore
	}
	return dns.MsgAccept
}

func (s *Server) connector(upstreamServer string) connector {
	upstream, err := parseUpstream(upstreamServer)
	// Resolvers close idle connections; a shared session cache lets
	// reconnects resume TLS 1.3 sessions instead of verifying certificates again.
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         upstream.serverName,
		ClientSessionCache: tls.NewLRUClientSessionCache(connectionsPerUpstream),
	}
	return func(ctx context.Context) (net.Conn, error) {
		if err != nil {
			return nil, err
		}
		return s.dial(ctx, upstream.address, cfg)
	}
}

// SetMaxStale configures how long expired positive answers can be served.
// A zero duration disables stale answers. Call it before Run.
func (s *Server) SetMaxStale(d time.Duration) { s.cache.maxStale = max(0, d) }

// Run serves TCP and UDP until cancellation or a listener error. A Server can run once.
func (s *Server) Run(ctx context.Context) (runErr error) {
	s.mu.Lock()
	if s.done != nil {
		s.mu.Unlock()
		return errors.New("server has already run")
	}
	ctx, cancel := context.WithCancel(ctx)
	s.runContext, s.cancel, s.done = ctx, cancel, make(chan struct{})
	s.mu.Unlock()
	defer close(s.done)
	defer cancel()
	if s.initErr != nil {
		return s.initErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)
	var running []*dns.Server
	defer func() {
		cancel()
		s.mu.Lock()
		s.stopping = true
		s.mu.Unlock()
		// Only the Run owner calls the library's non-idempotent Shutdown method.
		for _, srv := range running {
			srv.Shutdown(context.Background())
		}
		for _, p := range s.pools {
			p.shutdown()
		}
		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			runErr = err
		}
		s.workers.Wait()
	}()

	for i, srv := range s.servers {
		ready := make(chan error, 1)
		if srv.Net == "tcp" {
			srv.ListenFunc = func(srv *dns.Server) {
				listener := newTrackedListener(srv.Listener, maxTCPClients).(*trackedListener)
				srv.Listener = listener
				// The DNS library retries Accept errors indefinitely; stop on an
				// unexpected failure instead of leaving a dead listener spinning.
				g.Go(func() error {
					select {
					case err := <-listener.acceptErr:
						return err
					case <-ctx.Done():
						return nil
					}
				})
			}
		}
		srv.NotifyStartedFunc = func(context.Context) {
			s.mu.Lock()
			if srv.Listener != nil {
				srv.Addr = srv.Listener.Addr().String()
			}
			if srv.PacketConn != nil {
				srv.Addr = srv.PacketConn.LocalAddr().String()
			}
			s.mu.Unlock()
			ready <- nil
		}
		g.Go(func() error {
			err := srv.ListenAndServe()
			if err != nil {
				ready <- err
			}
			return err
		})
		// The callback establishes that initialization is complete before shutdown.
		if err := <-ready; err != nil {
			return err
		}
		running = append(running, srv)
		if err := ctx.Err(); err != nil {
			return err
		}
		// With an ephemeral port, keep TCP and UDP on the same selected port.
		if i == 0 && len(s.servers) > 1 {
			s.mu.Lock()
			_, port, _ := net.SplitHostPort(s.servers[1].Addr)
			if port == "0" {
				s.servers[1].Addr = srv.Addr
			}
			s.mu.Unlock()
		}
	}
	s.mu.Lock()
	s.startTime = time.Now()
	s.mu.Unlock()
	s.Log.Infof("DNS over TLS forwarder listening on %s (TCP and UDP)", s.servers[0].Addr)
	g.Go(func() error { s.refresher(ctx); return nil })
	<-ctx.Done()
	return ctx.Err()
}

// Shutdown stops the server and waits for its listeners and workers to exit.
// Repeated calls are safe; ctx bounds how long the caller waits.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.RLock()
	cancel, done := s.cancel, s.done
	s.mu.RUnlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ServeDNS implements miekg/dns.Handler for Server.
func (s *Server) ServeDNS(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) {
	network := "udp"
	if w.RemoteAddr() != nil && strings.HasPrefix(w.RemoteAddr().Network(), "tcp") {
		network = "tcp"
	}
	var malformed bool
	if q == nil {
		q = new(dns.Msg)
		malformed = true
	}
	// The DNS server initially unpacks only the question; validate all remaining sections.
	if len(q.Data) > 0 {
		if err := q.Unpack(); err != nil {
			malformed = true
		}
	}
	if len(q.Question) != 1 || q.Question[0] == nil {
		malformed = true
	}
	var m *dns.Msg
	if malformed {
		m = &dns.Msg{}
		m.ID, m.Response, m.Rcode = q.ID, true, dns.RcodeFormatError
	} else if q.Opcode != dns.OpcodeQuery {
		// Only standard queries are resolved; NOTIFY, UPDATE, and other
		// opcodes would only fail upstream.
		m = new(dns.Msg)
		dnsutil.SetReply(m, q)
		m.Rcode = dns.RcodeNotImplemented
	} else {
		if s.Log.GetLevel("debug") {
			s.Log.Debugf("Question from %v: %s", w.RemoteAddr(), q.String())
		}
		m = s.GetAnswer(ctx, q)
		if m == nil {
			m = new(dns.Msg)
			dnsutil.SetReply(m, q)
			m.Rcode = dns.RcodeServerFailure
		}
		// Cached/shared results must reflect this client's header flags.
		m.RecursionDesired, m.CheckingDisabled = q.RecursionDesired, q.CheckingDisabled
		m.AuthenticatedData = m.AuthenticatedData && (q.AuthenticatedData || q.Security)
		if q.UDPSize > 0 || q.Security || len(q.Pseudo) > 0 {
			// Advertise our own payload size; packResponse truncates to the
			// smaller of it and the client's.
			m.UDPSize, m.Security = ednsPayloadSize, q.Security
		} else {
			// A response carries OPT only when the query did (RFC 6891).
			m.UDPSize, m.Security, m.CompactAnswers, m.Delegation, m.Z = 0, false, false, false, 0
			m.Pseudo = slices.DeleteFunc(m.Pseudo, func(rr dns.RR) bool {
				_, ok := rr.(dns.EDNS0)
				return ok
			})
		}
	}
	if err := packResponse(m, q, network); err != nil {
		s.Log.Warnf("Unable to encode DNS response: %v", err)
		m = new(dns.Msg)
		m.ID, m.Response, m.Rcode = q.ID, true, dns.RcodeServerFailure
		if err := m.Pack(); err != nil {
			return
		}
	}
	s.metrics.recordQuery(network, m.Rcode)
	if s.Log.GetLevel("debug") {
		s.Log.Debugf("Answer to %v: %s", w.RemoteAddr(), m.String())
	}
	if _, err := m.WriteTo(w); err != nil {
		s.Log.Warnf("Write DNS response failed: %v", err)
	}
}

func packResponse(m, q *dns.Msg, network string) error {
	if err := m.Pack(); err != nil {
		return err
	}
	// Cap UDP replies at the flag-day size whatever the client advertises:
	// this avoids IP fragmentation and limits amplification.
	limit := max(dns.MinMsgSize, min(int(q.UDPSize), ednsPayloadSize))
	if network != "udp" || len(m.Data) <= limit {
		return nil
	}
	// Return a complete question with TC rather than split an RRset across packets.
	// The full cached answer remains available for the client's TCP retry.
	m.Truncated = true
	m.Answer, m.Ns, m.Extra = nil, nil, nil
	if err := m.Pack(); err != nil {
		return err
	}
	if len(m.Data) > limit {
		m.Pseudo = nil
		return m.Pack()
	}
	return nil
}

type debugStats struct {
	CacheMetrics            specialized.CacheMetrics
	CacheLen, CacheCap      int
	Uptime                  string
	TotalQueries            uint64
	CacheHits               uint64
	CacheMisses             uint64
	CacheRefreshes          uint64
	CacheStaleHits          uint64
	CacheRefreshesCompleted uint64
	CacheRefreshesDropped   uint64
	Deduplicated            uint64
	LookupsRejected         uint64
}

// DebugHandler returns an http.Handler that serves debug stats.
func (s *Server) DebugHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s.mu.RLock()
		uptime := time.Duration(0)
		if !s.startTime.IsZero() {
			uptime = time.Since(s.startTime)
		}
		s.mu.RUnlock()
		buf, err := json.MarshalIndent(debugStats{
			CacheMetrics:            s.cache.c.Metrics(),
			CacheLen:                s.cache.c.Len(),
			CacheCap:                s.cache.c.Cap(),
			Uptime:                  uptime.String(),
			TotalQueries:            s.metrics.QueriesTotal.Load(),
			CacheHits:               s.metrics.CacheHits.Load(),
			CacheMisses:             s.metrics.CacheMisses.Load(),
			CacheRefreshes:          s.metrics.CacheRefreshes.Load(),
			CacheStaleHits:          s.metrics.CacheStaleHits.Load(),
			CacheRefreshesCompleted: s.metrics.CacheRefreshesCompleted.Load(),
			CacheRefreshesDropped:   s.metrics.CacheRefreshesDropped.Load(),
			Deduplicated:            s.metrics.SingleflightDeduplicated.Load(),
			LookupsRejected:         s.metrics.LookupsRejected.Load(),
		}, "", " ")
		if err != nil {
			http.Error(w, "Unable to retrieve debug info", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(buf)
	})
}

// GetAnswer resolves q from the cache or the upstreams. A non-nil result
// carries q's ID and question spelling; nil means resolution failed.
func (s *Server) GetAnswer(ctx context.Context, q *dns.Msg) *dns.Msg {
	if q == nil || q.Response || len(q.Question) != 1 || q.Question[0] == nil {
		return nil
	}
	m, ok := s.cache.get(q)
	switch {
	case ok:
		s.metrics.CacheHits.Add(1)
	case m != nil:
		// Serve an expired entry with a short TTL while it is refreshed.
		s.metrics.CacheStaleHits.Add(1)
		s.refresh(q)
	default:
		s.metrics.CacheMisses.Add(1)
		m = s.forwardMessageAndCacheResponse(ctx, q)
	}
	if m != nil {
		// Cached and shared results may come from another client's query.
		m.ID, m.Question = q.ID, []dns.RR{q.Question[0].Clone()}
	}
	return m
}

func (s *Server) refresh(q *dns.Msg) {
	k := key(q)
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if _, pending := s.refreshPending[k]; pending {
		s.metrics.CacheRefreshesDropped.Add(1)
		return
	}
	s.refreshPending[k] = struct{}{}
	select {
	case s.rq <- CloneMsg(q):
		s.metrics.CacheRefreshes.Add(1)
	default:
		delete(s.refreshPending, k)
		s.metrics.CacheRefreshesDropped.Add(1)
	}
}

func (s *Server) refresher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-s.rq:
			s.forwardMessageAndCacheResponse(ctx, q)
			s.metrics.CacheRefreshesCompleted.Add(1)
			s.refreshMu.Lock()
			delete(s.refreshPending, key(q))
			s.refreshMu.Unlock()
		}
	}
}

func (s *Server) forwardMessageAndCacheResponse(ctx context.Context, q *dns.Msg) *dns.Msg {
	if err := ctx.Err(); err != nil {
		return nil
	}
	s.mu.RLock()
	if s.stopping {
		s.mu.RUnlock()
		return nil
	}
	s.workers.Add(1)
	s.mu.RUnlock()
	if !cacheableQuery(q) {
		defer s.workers.Done()
		lookupCtx, cancel := context.WithTimeout(ctx, connectionTimeout)
		defer cancel()
		return s.lookup(lookupCtx, q)
	}
	// A caller may stop waiting without canceling work needed by other callers.
	// The server context and a whole-lookup deadline still bound shared work.
	qc := CloneMsg(q)
	var executed atomic.Bool
	result := s.sf.DoChan(key(q), func() (any, error) {
		executed.Store(true)
		s.mu.RLock()
		serverCtx := s.runContext
		s.mu.RUnlock()
		if serverCtx == nil {
			serverCtx = context.Background()
		}
		lookupCtx, cancel := context.WithTimeout(serverCtx, connectionTimeout)
		defer cancel()
		m := s.lookup(lookupCtx, qc)
		if m == nil {
			return nil, errors.New("upstream resolution failed")
		}
		return m, nil
	})
	finish := func(result singleflight.Result) {
		if result.Shared && !executed.Load() {
			s.metrics.SingleflightDeduplicated.Add(1)
		}
		s.workers.Done()
	}
	select {
	case <-ctx.Done():
		// Retain ownership until shared work finishes, even after this caller leaves.
		go func() { finish(<-result) }()
		return nil
	case result := <-result:
		finish(result)
		if result.Err != nil || result.Val == nil {
			return nil
		}
		return CloneMsg(result.Val.(*dns.Msg))
	}
}

func (s *Server) lookup(ctx context.Context, q *dns.Msg) *dns.Msg {
	// Lookups queue for a few pooled connections per upstream. Failing fast
	// beyond the limit keeps memory bounded under floods of unique names.
	select {
	case s.lookups <- struct{}{}:
		defer func() { <-s.lookups }()
	default:
		s.metrics.LookupsRejected.Add(1)
		return nil
	}
	var m *dns.Msg
	for attempt := 0; attempt < lookupAttempts && ctx.Err() == nil; attempt++ {
		m = s.forwardMessageAndGetResponse(ctx, q)
		if m != nil {
			break
		}
	}
	if m == nil {
		s.Log.Warn("DNS upstream resolution failed")
		return nil
	}
	// Upstream padding (RFC 7830) and other per-hop options must not be
	// cached or forwarded over plain DNS. The upstream wire form is stale
	// from here on; dropping it also saves copying it into each clone.
	m.Pseudo = slices.DeleteFunc(m.Pseudo, strippedOption)
	m.Data = nil
	// The cache expires a response with its shortest record TTL, so the
	// floor applies to every section of a positive answer.
	if s.minTTL > 0 && positiveAnswer(q, m) {
		for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
			for _, rr := range section {
				rr.Header().TTL = max(rr.Header().TTL, uint32(s.minTTL))
			}
		}
	}
	s.cache.put(q, m)
	return m
}

func prepareOutboundQuery(q *dns.Msg) (*dns.Msg, error) {
	qc := CloneMsg(q)
	qc.Data = nil
	// Include the OPT record and option header before calculating the block size.
	padding := &dns.PADDING{}
	qc.Pseudo = append(slices.DeleteFunc(qc.Pseudo, strippedOption), padding)
	// The payload size is meaningless over TLS, but the DNS client
	// preallocates a response buffer of this size.
	qc.UDPSize = ednsPayloadSize
	if err := qc.Pack(); err != nil {
		return nil, err
	}
	padding.Padding = strings.Repeat("00", (128-len(qc.Data)%128)%128)
	if err := qc.Pack(); err != nil {
		return nil, err
	}
	return qc, nil
}

// forwardMessageAndGetResponse races q across the upstreams and returns the
// first NOERROR or NXDOMAIN response, or another response if none arrives.
// Losing exchanges finish in the background so their connections stay
// pooled; Run waits for them through s.workers.
func (s *Server) forwardMessageAndGetResponse(ctx context.Context, q *dns.Msg) *dns.Msg {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resps := make(chan *dns.Msg, len(s.pools))
	for _, p := range s.pools {
		s.workers.Add(1)
		go func(p *pool) {
			defer s.workers.Done()
			qc, err := prepareOutboundQuery(q)
			if err != nil {
				resps <- nil
				return
			}
			r, _ := s.exchangeMessages(ctx, p, qc)
			resps <- r
		}(p)
	}
	var fallback *dns.Msg
	for range s.pools {
		select {
		case <-ctx.Done():
			return nil
		case r := <-resps:
			if r == nil {
				continue
			}
			if r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError {
				return r
			}
			if fallback == nil {
				fallback = r
			}
		}
	}
	return fallback
}

var errNilResponse = errors.New("nil response from upstream")

// exchangeMessages sends q to one upstream. Resolvers close idle connections,
// so a failure on a pooled connection is retried on another one; a freshly
// dialed connection's failure is final.
func (s *Server) exchangeMessages(ctx context.Context, p *pool, q *dns.Msg) (*dns.Msg, error) {
	for attempt := 0; ; attempt++ {
		resp, reused, err := s.exchangeOnce(ctx, p, q)
		if err == nil || !reused || ctx.Err() != nil || attempt >= connectionsPerUpstream {
			return resp, err
		}
	}
}

// exchangeOnce checks out a connection while ctx allows, then completes the
// exchange even if ctx ends: reading the reply keeps the connection usable.
// Deadlines bound the exchange, and pool shutdown closes the connection.
func (s *Server) exchangeOnce(ctx context.Context, p *pool, q *dns.Msg) (resp *dns.Msg, reused bool, err error) {
	start := time.Now()
	defer func() {
		metricsErr := err
		if err != nil && p.ctx.Err() != nil {
			metricsErr = context.Canceled
		}
		s.metrics.recordUpstream(p.addr, time.Since(start), metricsErr)
	}()
	c, reused, err := p.acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	stop := context.AfterFunc(p.ctx, func() { _ = c.Close() })
	defer func() {
		if !stop() || err != nil {
			p.discard(c)
		} else {
			p.put(c)
		}
	}()
	// The DNS client sets a read deadline but none for the write.
	if err := c.SetWriteDeadline(time.Now().Add(exchangeWriteTimeout)); err != nil {
		return nil, reused, err
	}
	client := dns.NewClient()
	resp, _, err = client.ExchangeWithConn(p.ctx, q, c)
	if err != nil {
		return nil, reused, err
	}
	if resp == nil {
		return nil, reused, errNilResponse
	}
	if resp.Opcode != q.Opcode || len(resp.Question) != 1 || len(q.Question) != 1 ||
		!strings.EqualFold(resp.Question[0].Header().Name, q.Question[0].Header().Name) ||
		resp.Question[0].Header().Class != q.Question[0].Header().Class ||
		dns.RRToType(resp.Question[0]) != dns.RRToType(q.Question[0]) {
		return nil, reused, errors.New("upstream response does not match the question")
	}
	return resp, reused, nil
}
