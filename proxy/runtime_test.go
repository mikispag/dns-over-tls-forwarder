package proxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/gologme/log"
)

func runtimeServer(addr string) *Server {
	return NewServer(nil, log.New(io.Discard, "", 0), 100, false, 0, addr, "127.0.0.1:853")
}

func cacheRuntimeAnswer(s *Server, name string, count int) *dns.Msg {
	q := dns.NewMsg(name, dns.TypeA)
	m := new(dns.Msg)
	dnsutil.SetReply(m, q)
	for i := 0; i < count; i++ {
		rr, _ := dns.New(name + " 300 IN A 192.0.2.1")
		m.Answer = append(m.Answer, rr)
	}
	s.cache.put(q, m)
	return q
}

func TestUDPResponseLimit(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	q := cacheRuntimeAnswer(s, "large.test.", 100)
	for _, size := range []uint16{0, 512, 1232} {
		q.UDPSize = size
		if err := q.Pack(); err != nil {
			t.Fatal(err)
		}
		w := dnstest.NewTestRecorder()
		s.ServeDNS(context.Background(), w, q)
		if err := w.Msg.Unpack(); err != nil {
			t.Fatal(err)
		}
		if len(w.Msg.Data) > max(512, int(size)) || !w.Msg.Truncated {
			t.Errorf("UDPSize=%d: wire length=%d, TC=%v", size, len(w.Msg.Data), w.Msg.Truncated)
		}
	}
}

func TestQueryPaddingBlockSize(t *testing.T) {
	for _, q := range []*dns.Msg{
		dns.NewMsg("example.org.", dns.TypeA),
		dns.NewMsg(strings.Repeat("a", 63)+"."+strings.Repeat("b", 31)+".", dns.TypeA),
	} {
		for _, size := range []uint16{0, 1232} {
			q.UDPSize = size
			out, err := prepareOutboundQuery(q)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Data)%128 != 0 {
				t.Errorf("UDPSize=%d: wire length=%d", size, len(out.Data))
			}
			found := false
			for _, rr := range out.Pseudo {
				if _, ok := rr.(*dns.PADDING); ok {
					found = true
				}
			}
			if !found {
				t.Error("missing padding option")
			}
		}
	}
}

func TestPartialStartupClosesListeners(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	blocked, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocked.Close() }()
	s.servers[1].Addr = blocked.LocalAddr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Run(ctx); err == nil {
		t.Fatal("expected UDP bind error")
	}
	c, err := net.DialTimeout("tcp", s.servers[0].Addr, 100*time.Millisecond)
	if err == nil {
		_ = c.Close()
		t.Fatal("TCP listener remains open after failed startup")
	}
}

func TestWildcardUDPResponseSource(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("DNS dependency does not enable destination-address control messages on Windows")
	}
	// Linux routes the loopback /8 locally; macOS requires an explicit alias.
	// CI configures that alias so the source-address assertion runs on macOS.
	probe, err := net.ListenPacket("udp4", "127.0.0.2:0")
	if errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skip("secondary loopback address 127.0.0.2 is not configured; add a loopback alias")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	s := runtimeServer("0.0.0.0:0")
	q := cacheRuntimeAnswer(s, "source.test.", 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("shutdown timed out")
		}
	}()
	var port string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		_, port, _ = net.SplitHostPort(s.servers[1].Addr)
		started := !s.startTime.IsZero()
		s.mu.RUnlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	destination, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.2", port))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Pack(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo(q.Data, destination); err != nil {
		t.Fatal(err)
	}
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, source, err := c.ReadFrom(make([]byte, 2048))
	if err != nil {
		t.Fatal(err)
	}
	if source.String() != destination.String() {
		t.Errorf("query destination=%s response source=%s", destination, source)
	}
}

func TestOutboundQueryPackingError(t *testing.T) {
	q := dns.NewMsg(strings.Repeat("x", 64)+".test.", dns.TypeA)
	if _, err := prepareOutboundQuery(q); err == nil {
		t.Fatal("invalid label must fail packing")
	}
}

func TestMalformedExtraRejected(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	q := cacheRuntimeAnswer(s, "malformed.test.", 1)
	if err := q.Pack(); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(q.Data[10:12], 1) // Advertise an additional RR without its bytes.
	w := dnstest.NewTestRecorder()
	s.ServeDNS(context.Background(), w, q)
	if err := w.Msg.Unpack(); err != nil {
		t.Fatal(err)
	}
	if !w.Msg.Response || w.Msg.Rcode != dns.RcodeFormatError {
		t.Errorf("malformed query response: QR=%v rcode=%d", w.Msg.Response, w.Msg.Rcode)
	}
}

func TestResponseFlagsBelongToClient(t *testing.T) {
	for _, ad := range []bool{false, true} {
		s := runtimeServer("127.0.0.1:0")
		q := dns.NewMsg("flags.test.", dns.TypeA)
		q.RecursionDesired, q.CheckingDisabled, q.AuthenticatedData = false, true, ad
		m := new(dns.Msg)
		dnsutil.SetReply(m, q)
		m.RecursionDesired, m.CheckingDisabled, m.AuthenticatedData = true, false, true
		rr, _ := dns.New("flags.test. 300 IN A 192.0.2.1")
		m.Answer = []dns.RR{rr}
		s.cache.put(q, m)
		w := dnstest.NewTestRecorder()
		s.ServeDNS(context.Background(), w, q)
		if err := w.Msg.Unpack(); err != nil {
			t.Fatal(err)
		}
		if w.Msg.RecursionDesired || !w.Msg.CheckingDisabled || w.Msg.AuthenticatedData != ad {
			t.Errorf("AD request=%v: RD=%v CD=%v AD=%v", ad, w.Msg.RecursionDesired, w.Msg.CheckingDisabled, w.Msg.AuthenticatedData)
		}
	}
}

func TestUDPTruncationKeepsFullCachedAnswer(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	q := cacheRuntimeAnswer(s, "tcp-retry.test.", 100)
	w := dnstest.NewTestRecorder()
	s.ServeDNS(context.Background(), w, q)
	m, ok := s.cache.get(q)
	if !ok || len(m.Answer) != 100 || m.Truncated {
		t.Fatal("UDP truncation changed cached full answer")
	}
	if err := packResponse(m, q, "tcp"); err != nil {
		t.Fatal(err)
	}
	if len(m.Data) <= 512 || m.Truncated {
		t.Fatal("TCP response was truncated")
	}
}

func TestCanceledSingleflightCallerDoesNotCancelOtherWaiters(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	s.runContext = serverCtx
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var dials atomic.Int32
	s.dial = func(ctx context.Context, _ string, _ *tls.Config) (net.Conn, error) {
		dials.Add(1)
		client, peer := net.Pipe()
		go func() {
			defer func() { _ = peer.Close() }()
			q := new(dns.Msg)
			if _, err := q.ReadFrom(peer); err != nil {
				return
			}
			if err := q.Unpack(); err != nil {
				return
			}
			started <- struct{}{}
			<-release
			m := new(dns.Msg)
			dnsutil.SetReply(m, q)
			rr, _ := dns.New("shared.test. 300 IN A 192.0.2.1")
			m.Answer = []dns.RR{rr}
			if err := m.Pack(); err != nil {
				return
			}
			frame := make([]byte, 2, len(m.Data)+2)
			binary.BigEndian.PutUint16(frame, uint16(len(m.Data)))
			_, _ = peer.Write(append(frame, m.Data...))
		}()
		return client, nil
	}
	defer s.pools[0].shutdown()
	q := dns.NewMsg("shared.test.", dns.TypeA)
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	leader := make(chan *dns.Msg, 1)
	go func() { leader <- s.GetAnswer(callerCtx, q) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("lookup did not start")
	}
	cancelCaller()
	select {
	case m := <-leader:
		if m != nil {
			t.Fatal("canceled caller got answer")
		}
	case <-time.After(time.Second):
		t.Fatal("singleflight caller ignored cancellation")
	}
	// The original shared lookup is still in progress. This call must join it.
	joined := make(chan struct{})
	follower := make(chan *dns.Msg, 1)
	go func() { close(joined); follower <- s.GetAnswer(context.Background(), q) }()
	<-joined
	// Wait until the second caller is counted as a miss before releasing upstream.
	deadline := time.Now().Add(time.Second)
	for s.metrics.CacheMisses.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(release)
	select {
	case m := <-follower:
		if m == nil || len(m.Answer) != 1 {
			t.Fatal("remaining caller did not get answer")
		}
	case <-time.After(time.Second):
		t.Fatal("remaining caller blocked")
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("upstream dials=%d, want 1", got)
	}
	if got := s.metrics.SingleflightDeduplicated.Load(); got != 1 {
		t.Errorf("deduplicated followers=%d, want 1", got)
	}
}

func TestShutdownCancelsTLSHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	s := runtimeServer("127.0.0.1:0")
	s.pools = []*pool{newPoolWithAddr(1, listener.Addr().String(), s.connector(listener.Addr().String()))}
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); accepted <- c }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		started := !s.startTime.IsZero()
		s.mu.RUnlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	answer := make(chan *dns.Msg, 1)
	go func() { answer <- s.GetAnswer(context.Background(), dns.NewMsg("blocked.test.", dns.TypeA)) }()
	var peer net.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("TLS connection did not start")
	}
	if peer == nil {
		t.Fatal("accept failed")
	}
	defer func() { _ = peer.Close() }()
	shutdownCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown blocked on TLS handshake: %v", err)
	}
	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("repeated shutdown failed: %v", err)
	}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("Run still active")
	}
	select {
	case m := <-answer:
		if m != nil {
			t.Fatal("canceled lookup returned response")
		}
	case <-time.After(time.Second):
		t.Fatal("shared lookup survived shutdown")
	}
}

func TestRefreshQueueMetrics(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	s.rq = make(chan *dns.Msg, 1)
	s.dial = func(context.Context, string, *tls.Config) (net.Conn, error) {
		return nil, errors.New("test upstream unavailable")
	}
	q := dns.NewMsg("refresh.test.", dns.TypeA)
	s.refresh(q)
	s.refresh(q)
	s.refresh(dns.NewMsg("overflow.test.", dns.TypeA))
	if s.metrics.CacheRefreshes.Load() != 1 || s.metrics.CacheRefreshesDropped.Load() != 2 {
		t.Fatal("queue accounting includes rejected refreshes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.refresher(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for s.metrics.CacheRefreshesCompleted.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if s.metrics.CacheRefreshesCompleted.Load() != 1 {
		t.Fatal("completed refresh was not recorded")
	}
}

func FuzzDNSMessageTransforms(f *testing.F) {
	for _, name := range []string{"example.org.", strings.Repeat("x", 63) + ".test."} {
		q := dns.NewMsg(name, dns.TypeA)
		_ = q.Pack()
		f.Add(q.Data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		q := &dns.Msg{Data: append([]byte(nil), data...)}
		if err := q.Unpack(); err != nil || len(q.Question) != 1 {
			return
		}
		out, err := prepareOutboundQuery(q)
		if err != nil {
			return
		}
		if len(out.Data)%128 != 0 {
			t.Fatalf("padded length %d", len(out.Data))
		}
		decoded := &dns.Msg{Data: out.Data}
		if err := decoded.Unpack(); err != nil {
			t.Fatalf("padded message cannot unpack: %v", err)
		}
		for _, rr := range decoded.Pseudo {
			if _, ok := rr.(*dns.SUBNET); ok {
				t.Fatal("ECS survived normalization")
			}
		}
	})
}

func BenchmarkPrepareOutboundQuery(b *testing.B) {
	q := dns.NewMsg("example.org.", dns.TypeA)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := prepareOutboundQuery(q); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServeDNSCacheHit(b *testing.B) {
	s := runtimeServer("127.0.0.1:0")
	q := cacheRuntimeAnswer(s, "cached.test.", 1)
	w := dnstest.NewTestRecorder()
	b.ReportAllocs()
	for b.Loop() {
		s.ServeDNS(context.Background(), w, q)
	}
}

func TestShutdownWaitsForCanceledLookupWorkers(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	finishDial := make(chan struct{})
	s.dial = func(ctx context.Context, _ string, _ *tls.Config) (net.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		close(dialCanceled)
		<-finishDial
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		started := !s.startTime.IsZero()
		s.mu.RUnlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	callerDone := make(chan struct{})
	go func() { s.GetAnswer(callerCtx, dns.NewMsg("shutdown-wait.test.", dns.TypeA)); close(callerDone) }()
	<-dialStarted
	cancelCaller()
	<-callerDone
	cancel()
	<-dialCanceled
	select {
	case <-runDone:
		close(finishDial)
		t.Fatal("Run returned before canceled lookup worker finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(finishDial)
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("Run did not finish after lookup worker")
	}
}

func TestExchangeRejectsMismatchedQuestion(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	p := newPool(1, func(context.Context) (net.Conn, error) {
		client, peer := net.Pipe()
		go func() {
			defer func() { _ = peer.Close() }()
			q := new(dns.Msg)
			if _, err := q.ReadFrom(peer); err != nil {
				return
			}
			if err := q.Unpack(); err != nil {
				return
			}
			m := dns.NewMsg("wrong.test.", dns.TypeAAAA)
			m.ID = q.ID
			m.Response = true
			if err := m.Pack(); err != nil {
				return
			}
			frame := make([]byte, 2, len(m.Data)+2)
			binary.BigEndian.PutUint16(frame, uint16(len(m.Data)))
			_, _ = peer.Write(append(frame, m.Data...))
		}()
		return client, nil
	})
	defer p.shutdown()
	q := dns.NewMsg("wanted.test.", dns.TypeA)
	if _, err := s.exchangeMessages(context.Background(), p, q); err == nil {
		t.Fatal("same-ID response with wrong question was accepted")
	}
}

func TestShutdownClosesIdleTCPClients(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(ctx) }()
	var addr string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		started := !s.startTime.IsZero()
		addr = s.servers[0].Addr
		s.mu.RUnlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// Exchange once so the server has accepted the connection before shutdown.
	q := cacheRuntimeAnswer(s, "idle.test.", 1)
	if _, _, err := dns.NewClient().ExchangeWithConn(context.Background(), q, c); err != nil {
		t.Fatal(err)
	}
	shutdownCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("idle accepted TCP connection survived shutdown")
	}
	if err == nil {
		t.Fatal("idle TCP connection still readable")
	}
	<-runDone
}

func TestUnexpectedTCPListenerFailureIsReturned(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	var listener net.Listener
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		started := !s.startTime.IsZero()
		if started {
			listener = s.servers[0].Listener
		}
		s.mu.RUnlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if listener == nil {
		t.Fatal("server did not start")
	}
	underlying := listener.(*trackedListener).Listener
	if err := underlying.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("listener failure was hidden: %v", err)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("Run did not detect failed TCP listener")
	}
}

func TestWindowsListenAddressValidation(t *testing.T) {
	for _, addr := range []string{":53", "0.0.0.0:53", "[::]:53"} {
		if err := validateListenAddress(addr, "windows"); err == nil {
			t.Errorf("Windows wildcard %q was accepted", addr)
		}
		if err := validateListenAddress(addr, "linux"); err != nil {
			t.Errorf("Linux wildcard %q was rejected: %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:53", "[::1]:53", "192.0.2.1:53", "localhost:53"} {
		if err := validateListenAddress(addr, "windows"); err != nil {
			t.Errorf("Windows explicit address %q was rejected: %v", addr, err)
		}
	}
}
