package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"slices"
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

func TestUpstreamMetricsSorted(t *testing.T) {
	s := runtimeServer("127.0.0.1:0")
	upstreams := []string{"c:853", "a:853", "d:853", "b:853"}
	for _, u := range upstreams {
		s.metrics.recordUpstream(u, time.Millisecond, nil)
	}
	w := httptest.NewRecorder()
	s.PrometheusHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, family := range []string{"dns_upstream_requests_total", "dns_upstream_errors_total", "dns_upstream_duration_seconds_total"} {
		var got []string
		for _, line := range strings.Split(w.Body.String(), "\n") {
			if rest, ok := strings.CutPrefix(line, family+`{upstream="`); ok {
				got = append(got, rest[:strings.IndexByte(rest, '"')])
			}
		}
		if !slices.IsSorted(got) || len(got) != len(upstreams) {
			t.Errorf("%s upstream order = %v, want %d sorted labels", family, got, len(upstreams))
		}
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
