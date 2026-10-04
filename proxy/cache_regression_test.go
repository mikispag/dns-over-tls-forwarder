package proxy

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

func cacheTestAnswer(t *testing.T, q *dns.Msg, records ...string) *dns.Msg {
	t.Helper()
	r := new(dns.Msg)
	dnsutil.SetReply(r, q)
	for _, text := range records {
		rr, err := dns.New(text)
		if err != nil {
			t.Fatal(err)
		}
		r.Answer = append(r.Answer, rr)
	}
	return r
}

func TestCacheQueryPolicyIsolation(t *testing.T) {
	for _, flag := range []string{"CD", "RD", "AD", "DO"} {
		t.Run(flag, func(t *testing.T) {
			c, _ := newCache(10, false)
			q := dns.NewMsg("example.test.", dns.TypeA)
			r := cacheTestAnswer(t, q, "example.test. 300 IN A 192.0.2.1")
			c.put(q, r)
			switch flag {
			case "CD":
				q.CheckingDisabled = !q.CheckingDisabled
			case "RD":
				q.RecursionDesired = !q.RecursionDesired
			case "AD":
				q.AuthenticatedData = !q.AuthenticatedData
			case "DO":
				q.Security = !q.Security
			}
			if got, hit := c.get(q); hit || got != nil {
				t.Fatalf("query with different %s reused cached answer", flag)
			}
		})
	}
}

func TestCacheRejectsUncacheableResponses(t *testing.T) {
	for _, kind := range []string{"truncated", "no SOA", "referral", "zero answer TTL", "zero additional TTL", "high TTL bit"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := newCache(10, false)
			q := dns.NewMsg("example.test.", dns.TypeA)
			r := cacheTestAnswer(t, q, "example.test. 300 IN A 192.0.2.1")
			switch kind {
			case "truncated":
				r.Truncated = true
			case "no SOA":
				r.Rcode, r.Answer = dns.RcodeNameError, nil
			case "referral":
				r.Answer = nil
				ns, _ := dns.New("example.test. 300 IN NS ns.example.test.")
				r.Ns = []dns.RR{ns}
			case "zero answer TTL":
				r.Answer[0].Header().TTL = 0
			case "zero additional TTL":
				glue, _ := dns.New("ns.example.test. 0 IN A 192.0.2.2")
				r.Extra = []dns.RR{glue}
			case "high TTL bit":
				r.Answer[0].Header().TTL = 1 << 31
			}
			c.put(q, r)
			if got, hit := c.get(q); hit || got != nil {
				t.Fatalf("cached %s response", kind)
			}
		})
	}
}

func TestCacheUnknownEDNSBypass(t *testing.T) {
	c, _ := newCache(10, false)
	q := dns.NewMsg("example.test.", dns.TypeA)
	q.Pseudo = []dns.RR{new(dns.COOKIE)}
	c.put(q, cacheTestAnswer(t, q, "example.test. 300 IN A 192.0.2.1"))
	if got, hit := c.get(q); hit || got != nil {
		t.Fatal("cached client-specific EDNS response")
	}
}

func TestCacheRefreshInvalidatesUncacheableSuccess(t *testing.T) {
	c, _ := newCache(10, false)
	q := dns.NewMsg("example.test.", dns.TypeA)
	r := cacheTestAnswer(t, q, "example.test. 300 IN A 192.0.2.1")
	c.put(q, r)
	r.Answer[0].Header().TTL = 0
	c.put(q, r)
	if got, hit := c.get(q); hit || got != nil {
		t.Fatal("zero-TTL refresh left previous answer cached")
	}
}

func TestCacheAuthorityTTLNotIncreased(t *testing.T) {
	c, _ := newCache(10, false)
	q := dns.NewMsg("example.test.", dns.TypeA)
	r := cacheTestAnswer(t, q, "example.test. 3600 IN A 192.0.2.1")
	ns, _ := dns.New("example.test. 10 IN NS ns.example.test.")
	r.Ns = []dns.RR{ns}
	c.put(q, r)
	got, hit := c.get(q)
	if !hit || got.Ns[0].Header().TTL > 10 {
		t.Fatal("authority TTL increased on cache hit")
	}
}

func TestCacheOldStaleAndNegativeMiss(t *testing.T) {
	for _, negative := range []bool{false, true} {
		c, _ := newCache(10, false)
		q := dns.NewMsg("example.test.", dns.TypeA)
		r := cacheTestAnswer(t, q, "example.test. 300 IN A 192.0.2.1")
		if negative {
			r.Rcode, r.Answer = dns.RcodeNameError, nil
		}
		c.c.Put(key(q), cacheValue{m: r, exp: time.Now().Add(-365 * 24 * time.Hour)})
		if got, _ := c.get(q); got != nil {
			t.Fatalf("served obsolete entry (negative=%v)", negative)
		}
	}
}

func TestCacheAgesEverySection(t *testing.T) {
	c, _ := newCache(10, false)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	c.maxStale = 0
	q := dns.NewMsg("example.test.", dns.TypeA)
	r := cacheTestAnswer(t, q, "example.test. 300 IN A 192.0.2.1")
	ns, _ := dns.New("example.test. 100 IN NS ns.example.test.")
	glue, _ := dns.New("ns.example.test. 50 IN A 192.0.2.2")
	r.Ns, r.Extra = []dns.RR{ns}, []dns.RR{glue}
	c.put(q, r)
	now = now.Add(10 * time.Second)
	got, hit := c.get(q)
	if !hit {
		t.Fatal("fresh entry missed")
	}
	if got.Answer[0].Header().TTL != 290 || got.Ns[0].Header().TTL != 90 || got.Extra[0].Header().TTL != 40 {
		t.Fatalf("incorrect TTL aging: answer=%d authority=%d additional=%d", got.Answer[0].Header().TTL, got.Ns[0].Header().TTL, got.Extra[0].Header().TTL)
	}
	now = now.Add(40 * time.Second)
	if got, hit := c.get(q); hit || got != nil {
		t.Fatal("complete response remained fresh after additional record expired")
	}
}

func TestCacheNegativeTTLs(t *testing.T) {
	for _, tc := range []struct {
		name           string
		soaTTL, minttl uint32
		want           uint32
	}{
		{"minimum", 600, 20, 20},
		{"SOA TTL", 10, 600, 10},
		{"cap", 600, 600, 300},
		{"zero", 600, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newCache(10, false)
			now := time.Unix(1_700_000_000, 0)
			c.now = func() time.Time { return now }
			q := dns.NewMsg("example.test.", dns.TypeA)
			r := cacheTestAnswer(t, q)
			r.Rcode = dns.RcodeNameError
			soa, _ := dns.New("example.test. 600 IN SOA ns.test. hostmaster.test. 1 7200 3600 1209600 600")
			soa.Header().TTL, soa.(*dns.SOA).Minttl = tc.soaTTL, tc.minttl
			r.Ns = []dns.RR{soa}
			c.put(q, r)
			got, hit := c.get(q)
			if tc.want == 0 {
				if got != nil || hit {
					t.Fatal("cached zero negative TTL")
				}
				return
			}
			if !hit || got.Ns[0].Header().TTL != tc.want {
				t.Fatalf("negative TTL: got %v hit=%v, want %d", got, hit, tc.want)
			}
			now = now.Add(time.Duration(tc.want) * time.Second)
			if got, hit := c.get(q); hit || got != nil {
				t.Fatal("served expired negative response")
			}
		})
	}
}

func TestCacheStalePolicy(t *testing.T) {
	for _, kind := range []string{"positive", "disabled", "past limit", "negative", "CNAME NODATA", "DO", "AD query", "AD response", "RRSIG"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := newCache(10, false)
			now := time.Unix(1_700_000_000, 0)
			c.now = func() time.Time { return now }
			q := dns.NewMsg("example.test.", dns.TypeA)
			r := cacheTestAnswer(t, q, "example.test. 10 IN A 192.0.2.1")
			switch kind {
			case "disabled":
				c.maxStale = 0
			case "negative", "CNAME NODATA":
				r.Rcode, r.Answer = dns.RcodeNameError, nil
				if kind == "CNAME NODATA" {
					r = cacheTestAnswer(t, q, "example.test. 10 IN CNAME other.test.")
				}
				soa, _ := dns.New("example.test. 10 IN SOA ns.test. hostmaster.test. 1 7200 3600 1209600 10")
				r.Ns = []dns.RR{soa}
			case "DO":
				q.Security = true
			case "AD query":
				q.AuthenticatedData = true
			case "AD response":
				r.AuthenticatedData = true
			case "RRSIG":
				r.Answer = append(r.Answer, &dns.RRSIG{Hdr: dns.Header{Name: "example.test.", TTL: 10}})
			}
			c.put(q, r)
			now = now.Add(10 * time.Second)
			if kind == "past limit" {
				now = now.Add(time.Hour)
			}
			got, hit := c.get(q)
			if kind == "positive" {
				if got == nil || hit || got.Answer[0].Header().TTL != 30 {
					t.Fatalf("expected positive stale reply with refresh: got=%v hit=%v", got, hit)
				}
			} else if got != nil || hit {
				t.Fatalf("served disallowed stale response (%s)", kind)
			}
		})
	}
}

func TestCacheTransientFailurePreservesStale(t *testing.T) {
	c, _ := newCache(10, false)
	now := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return now }
	q := dns.NewMsg("example.test.", dns.TypeA)
	c.put(q, cacheTestAnswer(t, q, "example.test. 10 IN A 192.0.2.1"))
	now = now.Add(10 * time.Second)
	failure := cacheTestAnswer(t, q)
	failure.Rcode = dns.RcodeServerFailure
	c.put(q, failure)
	if got, hit := c.get(q); got == nil || hit {
		t.Fatal("transient failure discarded the stale fallback")
	}
}
