package proxy

import (
	"time"

	"codeberg.org/miekg/dns"
	"github.com/gologme/log"
	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
)

const (
	// Maximum TTL to cache, set to 2^31 - 1. See: https://tools.ietf.org/html/rfc1034.
	maxTTL = 2147483647 * time.Second
)

type cache struct {
	c *specialized.Cache
}

type cacheValue struct {
	m   *dns.Msg
	exp time.Time
}

func newCache(size int, evictMetrics bool) (*cache, error) {
	c, err := specialized.NewCache(size, evictMetrics)
	if err != nil {
		return nil, err
	}
	return &cache{c}, nil
}

func (c *cache) get(mk *dns.Msg) (*dns.Msg, bool) {
	if c == nil || mk == nil || len(mk.Question) == 0 {
		return nil, false
	}

	k := key(mk)
	r, ok := c.c.Get(k)
	if !ok || r == nil {
		log.Debugf("[CACHE] MISS %q", k)
		return nil, false
	}
	v := r.(cacheValue)
	mv := CloneMsg(v.m)
	// Rewrite the answer ID to match the question ID.
	mv.ID = mk.ID
	now := time.Now().UTC()
	// If the TTL has expired, speculatively return the cache entry anyway with a short TTL, and refresh it.
	if v.exp.Before(now) {
		log.Debugf("[CACHE] MISS + REFRESH due to expired TTL for %q", k)
		// Set a very short TTL
		for _, a := range mv.Answer {
			a.Header().TTL = 60
		}
		for _, a := range mv.Ns {
			a.Header().TTL = 60
		}
		return mv, false
	}
	log.Debugf("[CACHE] HIT %q", k)
	// Rewrite the TTL.
	remainingTTL := uint32(max(1, int64(time.Until(v.exp).Seconds())))
	for _, a := range mv.Answer {
		a.Header().TTL = remainingTTL
	}
	for _, a := range mv.Ns {
		a.Header().TTL = remainingTTL
	}
	return mv, true
}

func (c *cache) put(k *dns.Msg, v *dns.Msg) {
	if c == nil || v == nil || k == nil || len(k.Question) == 0 {
		return
	}

	cacheKey := key(k)
	// Only cache NOERROR (with answers or NODATA) and NXDOMAIN (RFC 2308).
	if v.Rcode != dns.RcodeSuccess && v.Rcode != dns.RcodeNameError {
		log.Debugf("[CACHE] Did not cache error answer (%v) for %q", dns.RcodeToString[v.Rcode], cacheKey)
		return
	}

	now := time.Now().UTC()
	var minTTLSec uint32 = 300 // default negative TTL cap (5 min)

	if v.Rcode == dns.RcodeSuccess && len(v.Answer) > 0 {
		minTTLSec = uint32(maxTTL / time.Second)
		for _, a := range v.Answer {
			if ttl := a.Header().TTL; ttl < minTTLSec {
				minTTLSec = ttl
			}
		}
	} else {
		// RFC 2308: For NXDOMAIN or NODATA, inspect SOA record in the Authority (Ns) section
		hasSOA := false
		for _, rr := range v.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				hasSOA = true
				minTTLSec = soa.Minttl
				if soa.Header().TTL < minTTLSec {
					minTTLSec = soa.Header().TTL
				}
				break
			}
		}
		if !hasSOA {
			minTTLSec = 60 // sensible default when no SOA is returned
		}
		// Cap negative TTL at 300 seconds
		if minTTLSec > 300 {
			minTTLSec = 300
		}
		log.Debugf("[CACHE] Negative cache entry (%v) for %q with TTL %ds", dns.RcodeToString[v.Rcode], cacheKey, minTTLSec)
	}

	if minTTLSec == 0 {
		return
	}

	exp := now.Add(time.Duration(minTTLSec) * time.Second)
	cm := CloneMsg(v)
	// Always set the TC bit to off.
	cm.Truncated = false

	c.c.Put(cacheKey, cacheValue{m: cm, exp: exp})
}

func key(k *dns.Msg) string {
	if k == nil || len(k.Question) == 0 {
		return ""
	}
	if k.Security {
		return k.Question[0].String() + ":do=1"
	}
	return k.Question[0].String() + ":do=0"
}
