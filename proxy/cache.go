package proxy

import (
	"fmt"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
)

const (
	// Maximum TTL to cache, set to 2^31 - 1 (RFC 2181, Section 8).
	maxTTL = 2147483647 * time.Second
)

type cache struct {
	c        *specialized.Cache
	now      func() time.Time
	maxStale time.Duration
}

type cacheValue struct {
	m      *dns.Msg
	stored time.Time
	exp    time.Time
}

func newCache(size int, evictMetrics bool) (*cache, error) {
	c, err := specialized.NewCache(size, evictMetrics)
	if err != nil {
		return nil, err
	}
	return &cache{c: c, now: time.Now, maxStale: time.Hour}, nil
}

func (c *cache) get(mk *dns.Msg) (*dns.Msg, bool) {
	if c == nil || !cacheableQuery(mk) {
		return nil, false
	}

	k := key(mk)
	r, ok := c.c.Get(k)
	if !ok || r == nil {
		return nil, false
	}
	v := r.(cacheValue)
	now := c.now()
	stale := !now.Before(v.exp)
	if stale && (c.maxStale <= 0 || !now.Before(v.exp.Add(c.maxStale)) || !staleAllowed(mk, v.m)) {
		return nil, false
	}
	mv := CloneMsg(v.m)
	mv.ID = mk.ID
	elapsed := uint32(max(0, now.Sub(v.stored)/time.Second))
	for _, section := range [][]dns.RR{mv.Answer, mv.Ns, mv.Extra} {
		for _, rr := range section {
			if _, opt := rr.(*dns.OPT); opt {
				continue
			}
			if stale {
				rr.Header().TTL = 30
			} else {
				rr.Header().TTL -= min(rr.Header().TTL, elapsed)
			}
		}
	}
	return mv, !stale
}

func (c *cache) put(k *dns.Msg, v *dns.Msg) {
	if c == nil || v == nil || !cacheableQuery(k) {
		return
	}

	cacheKey := key(k)
	// Only cache NOERROR (with answers or NODATA) and NXDOMAIN (RFC 2308).
	if v.Rcode != dns.RcodeSuccess && v.Rcode != dns.RcodeNameError {
		return
	}
	if v.Truncated {
		return
	}

	minTTLSec := uint32(maxTTL / time.Second)
	negative := !positiveAnswer(k, v)
	if negative {
		// RFC 2308: For NXDOMAIN or NODATA, inspect SOA record in the Authority (Ns) section
		hasSOA := false
		for _, rr := range v.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				hasSOA = true
				minTTLSec = min(soa.Minttl, soa.Header().TTL, 300)
				break
			}
		}
		if !hasSOA {
			c.c.Remove(cacheKey)
			return
		}
	}
	// Expire the complete response when any real record expires. Keep each
	// record's original TTL so a hit ages every section without increasing TTLs.
	for _, section := range [][]dns.RR{v.Answer, v.Ns, v.Extra} {
		for _, rr := range section {
			if _, opt := rr.(*dns.OPT); opt {
				continue
			}
			ttl := rr.Header().TTL
			if ttl > uint32(maxTTL/time.Second) {
				ttl = 0 // RFC 2181: a TTL with its high bit set is zero.
			}
			minTTLSec = min(minTTLSec, ttl)
		}
	}

	if minTTLSec == 0 {
		c.c.Remove(cacheKey)
		return
	}

	now := c.now()
	exp := now.Add(time.Duration(minTTLSec) * time.Second)
	cm := CloneMsg(v)
	cm.Data = nil
	if negative {
		for _, rr := range cm.Ns {
			if _, soa := rr.(*dns.SOA); soa {
				rr.Header().TTL = minTTLSec
			}
		}
	}
	c.c.Put(cacheKey, cacheValue{m: cm, stored: now, exp: exp})
}

// Only options normalized before forwarding can safely share cached responses.
func cacheableQuery(q *dns.Msg) bool {
	if q == nil || len(q.Question) != 1 || q.Opcode != dns.OpcodeQuery || q.Version != 0 || q.CompactAnswers || q.Delegation || len(q.Answer)+len(q.Ns)+len(q.Extra) != 0 {
		return false
	}
	for _, rr := range q.Pseudo {
		switch rr.(type) {
		case *dns.PADDING, *dns.SUBNET:
		default:
			return false
		}
	}
	return true
}

func staleAllowed(q, m *dns.Msg) bool {
	if !positiveAnswer(q, m) || q.Security || q.AuthenticatedData || m.Security || m.AuthenticatedData {
		return false
	}
	for _, section := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				return false
			}
		}
	}
	return true
}

func positiveAnswer(q, m *dns.Msg) bool {
	if m.Rcode != dns.RcodeSuccess {
		return false
	}
	qtype := dns.RRToType(q.Question[0])
	for _, rr := range m.Answer {
		if qtype == dns.TypeANY || dns.RRToType(rr) == qtype {
			return true
		}
	}
	return false
}

func key(k *dns.Msg) string {
	if k == nil || len(k.Question) == 0 {
		return ""
	}
	return fmt.Sprintf("%s:do=%t:cd=%t:rd=%t:ad=%t", k.Question[0].String(), k.Security, k.CheckingDisabled, k.RecursionDesired, k.AuthenticatedData)
}
