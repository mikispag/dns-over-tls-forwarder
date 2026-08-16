package proxy

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ServerMetrics stores operational statistics for the DNS-over-TLS proxy.
type ServerMetrics struct {
	QueriesTotal     atomic.Uint64
	QueriesUDP       atomic.Uint64
	QueriesTCP       atomic.Uint64
	QueriesSuccess   atomic.Uint64
	QueriesNXDomain  atomic.Uint64
	QueriesServFail  atomic.Uint64
	QueriesFormErr   atomic.Uint64
	QueriesOtherErr  atomic.Uint64

	CacheHits        atomic.Uint64
	CacheMisses      atomic.Uint64
	CacheRefreshes   atomic.Uint64

	SingleflightDeduplicated atomic.Uint64

	upstreamMu      sync.Mutex
	upstreamStats   map[string]*upstreamStat
}

type upstreamStat struct {
	requests atomic.Uint64
	errors   atomic.Uint64
	duration atomic.Uint64 // nanoseconds total
}

func newServerMetrics() *ServerMetrics {
	return &ServerMetrics{
		upstreamStats: make(map[string]*upstreamStat),
	}
}

func (m *ServerMetrics) recordQuery(net string, rcode uint16) {
	m.QueriesTotal.Add(1)
	if net == "tcp" {
		m.QueriesTCP.Add(1)
	} else {
		m.QueriesUDP.Add(1)
	}

	switch rcode {
	case 0: // NOERROR
		m.QueriesSuccess.Add(1)
	case 3: // NXDOMAIN
		m.QueriesNXDomain.Add(1)
	case 2: // SERVFAIL
		m.QueriesServFail.Add(1)
	case 1: // FORMERR
		m.QueriesFormErr.Add(1)
	default:
		m.QueriesOtherErr.Add(1)
	}
}

func (m *ServerMetrics) recordUpstream(upstream string, dur time.Duration, err error) {
	m.upstreamMu.Lock()
	stat, ok := m.upstreamStats[upstream]
	if !ok {
		stat = &upstreamStat{}
		m.upstreamStats[upstream] = stat
	}
	m.upstreamMu.Unlock()

	stat.requests.Add(1)
	if err != nil {
		stat.errors.Add(1)
	}
	stat.duration.Add(uint64(dur.Nanoseconds()))
}

// PrometheusHandler exports metrics in Prometheus text exposition format.
func (s *Server) PrometheusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		s.mu.Lock()
		uptimeSeconds := time.Since(s.startTime).Seconds()
		s.mu.Unlock()

		cacheLen := 0
		cacheCap := 0
		if s.cache != nil && s.cache.c != nil {
			cacheLen = s.cache.c.Len()
			cacheCap = s.cache.c.Cap()
		}

		fmt.Fprintf(w, "# HELP dns_uptime_seconds Total time the server has been running in seconds.\n")
		fmt.Fprintf(w, "# TYPE dns_uptime_seconds gauge\n")
		fmt.Fprintf(w, "dns_uptime_seconds %.2f\n\n", uptimeSeconds)

		fmt.Fprintf(w, "# HELP dns_queries_total Total number of DNS queries received.\n")
		fmt.Fprintf(w, "# TYPE dns_queries_total counter\n")
		fmt.Fprintf(w, "dns_queries_total{protocol=\"udp\"} %d\n", s.metrics.QueriesUDP.Load())
		fmt.Fprintf(w, "dns_queries_total{protocol=\"tcp\"} %d\n\n", s.metrics.QueriesTCP.Load())

		fmt.Fprintf(w, "# HELP dns_responses_total Total number of DNS responses sent by RCODE.\n")
		fmt.Fprintf(w, "# TYPE dns_responses_total counter\n")
		fmt.Fprintf(w, "dns_responses_total{rcode=\"NOERROR\"} %d\n", s.metrics.QueriesSuccess.Load())
		fmt.Fprintf(w, "dns_responses_total{rcode=\"NXDOMAIN\"} %d\n", s.metrics.QueriesNXDomain.Load())
		fmt.Fprintf(w, "dns_responses_total{rcode=\"SERVFAIL\"} %d\n", s.metrics.QueriesServFail.Load())
		fmt.Fprintf(w, "dns_responses_total{rcode=\"FORMERR\"} %d\n", s.metrics.QueriesFormErr.Load())
		fmt.Fprintf(w, "dns_responses_total{rcode=\"OTHER\"} %d\n\n", s.metrics.QueriesOtherErr.Load())

		fmt.Fprintf(w, "# HELP dns_cache_hits_total Total number of cache hits.\n")
		fmt.Fprintf(w, "# TYPE dns_cache_hits_total counter\n")
		fmt.Fprintf(w, "dns_cache_hits_total %d\n\n", s.metrics.CacheHits.Load())

		fmt.Fprintf(w, "# HELP dns_cache_misses_total Total number of cache misses.\n")
		fmt.Fprintf(w, "# TYPE dns_cache_misses_total counter\n")
		fmt.Fprintf(w, "dns_cache_misses_total %d\n\n", s.metrics.CacheMisses.Load())

		fmt.Fprintf(w, "# HELP dns_cache_refreshes_total Total number of background refreshes for expired entries.\n")
		fmt.Fprintf(w, "# TYPE dns_cache_refreshes_total counter\n")
		fmt.Fprintf(w, "dns_cache_refreshes_total %d\n\n", s.metrics.CacheRefreshes.Load())

		fmt.Fprintf(w, "# HELP dns_cache_entries Current number of entries in cache.\n")
		fmt.Fprintf(w, "# TYPE dns_cache_entries gauge\n")
		fmt.Fprintf(w, "dns_cache_entries %d\n\n", cacheLen)

		fmt.Fprintf(w, "# HELP dns_cache_capacity Maximum capacity of the cache.\n")
		fmt.Fprintf(w, "# TYPE dns_cache_capacity gauge\n")
		fmt.Fprintf(w, "dns_cache_capacity %d\n\n", cacheCap)

		fmt.Fprintf(w, "# HELP dns_singleflight_deduplications_total Total number of concurrent duplicate upstream requests deduplicated.\n")
		fmt.Fprintf(w, "# TYPE dns_singleflight_deduplications_total counter\n")
		fmt.Fprintf(w, "dns_singleflight_deduplications_total %d\n\n", s.metrics.SingleflightDeduplicated.Load())

		s.metrics.upstreamMu.Lock()
		defer s.metrics.upstreamMu.Unlock()

		if len(s.metrics.upstreamStats) > 0 {
			fmt.Fprintf(w, "# HELP dns_upstream_requests_total Total number of queries forwarded to upstream servers.\n")
			fmt.Fprintf(w, "# TYPE dns_upstream_requests_total counter\n")
			for u, stat := range s.metrics.upstreamStats {
				fmt.Fprintf(w, "dns_upstream_requests_total{upstream=%q} %d\n", u, stat.requests.Load())
			}
			fmt.Fprintf(w, "\n# HELP dns_upstream_errors_total Total number of errors encountered from upstream servers.\n")
			fmt.Fprintf(w, "# TYPE dns_upstream_errors_total counter\n")
			for u, stat := range s.metrics.upstreamStats {
				fmt.Fprintf(w, "dns_upstream_errors_total{upstream=%q} %d\n", u, stat.errors.Load())
			}
			fmt.Fprintf(w, "\n# HELP dns_upstream_duration_seconds_total Total duration in seconds spent waiting for upstream responses.\n")
			fmt.Fprintf(w, "# TYPE dns_upstream_duration_seconds_total counter\n")
			for u, stat := range s.metrics.upstreamStats {
				durSec := float64(stat.duration.Load()) / 1e9
				fmt.Fprintf(w, "dns_upstream_duration_seconds_total{upstream=%q} %.6f\n", u, durSec)
			}
			fmt.Fprintf(w, "\n")
		}
	})
}
