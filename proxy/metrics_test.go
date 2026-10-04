package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/gologme/log"
)

func TestMetricsBeforeStartup(t *testing.T) {
	s := NewServer(dns.NewServeMux(), log.New(io.Discard, "", 0), 0, false, 0, "127.0.0.1:0")
	w := httptest.NewRecorder()
	s.PrometheusHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), "dns_uptime_seconds 0.00\n") {
		t.Fatalf("unstarted server must report zero uptime: %s", w.Body.String())
	}
}

func TestUpstreamCancellationMetrics(t *testing.T) {
	m := newServerMetrics()
	m.recordUpstream("resolver", time.Millisecond, context.Canceled)
	m.recordUpstream("resolver", time.Millisecond, fmt.Errorf("dial: %w", context.Canceled))
	m.recordUpstream("resolver", time.Millisecond, context.DeadlineExceeded)
	m.recordUpstream("resolver", time.Millisecond, nil)
	stats := m.upstreamStats["resolver"]
	if stats.requests.Load() != 4 || stats.errors.Load() != 1 {
		t.Fatalf("requests=%d errors=%d; canceled races must not count as failures", stats.requests.Load(), stats.errors.Load())
	}
}
