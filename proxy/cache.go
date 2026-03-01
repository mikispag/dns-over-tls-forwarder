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
	if c == nil {
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
	// If the TTL has expired, speculatively return the cache entry anyway with a short TTL, and refresh it.
	if v.exp.Before(time.Now().UTC()) {
		log.Debugf("[CACHE] MISS + REFRESH due to expired TTL for %q", k)
		// Set a very short TTL
		for _, a := range mv.Answer {
			a.Header().TTL = 60
		}
		return mv, false
	}
	log.Debugf("[CACHE] HIT %q", k)
	// Rewrite the TTL.
	for _, a := range mv.Answer {
		a.Header().TTL = uint32(time.Since(v.exp).Seconds() * -1)
	}
	return mv, true
}

func (c *cache) put(k *dns.Msg, v *dns.Msg) {
	if c == nil {
		return
	}

	now := time.Now().UTC()
	minExpirationTime := now.Add(maxTTL)
	cacheKey := key(k)
	// Do not cache DNS errors.
	if v.Rcode != dns.RcodeSuccess {
		log.Debugf("[CACHE] Did not cache error answer (%v) for %q", dns.RcodeToString[v.Rcode], cacheKey)
		return
	}
	for _, a := range v.Answer {
		ttl := time.Duration(a.Header().TTL) * time.Second
		exp := now.Add(ttl)
		if exp.Before(minExpirationTime) {
			minExpirationTime = exp
		}
	}
	cm := CloneMsg(v)
	// Always set the TC bit to off.
	cm.Truncated = false

	c.c.Put(cacheKey, cacheValue{m: cm, exp: minExpirationTime})
}

func key(k *dns.Msg) string {
	return k.Question[0].String()
}
