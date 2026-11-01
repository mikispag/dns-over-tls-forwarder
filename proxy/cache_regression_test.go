package proxy

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnstest"
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
	// A zone-version request expects a response from the answering server.
	q.Pseudo = []dns.RR{new(dns.ZONEVERSION)}
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

func TestCacheKeySeparatesQuestionTypeAndClass(t *testing.T) {
	seen := make(map[string]string)
	check := func(desc string, q *dns.Msg) {
		t.Helper()
		k := key(q)
		if prev, dup := seen[k]; dup {
			t.Errorf("%s shares cache key %q with %s", desc, k, prev)
		}
		seen[k] = desc
	}
	// The DNS library formats these meta-type questions without their type.
	for _, qtype := range []uint16{dns.TypeA, dns.TypeANY, dns.TypeAXFR, dns.TypeIXFR, dns.TypeNXNAME, dns.TypeOPT} {
		check(dns.TypeToString[qtype], dns.NewMsg("example.test.", qtype))
	}
	check("OPT other name", dns.NewMsg("other.test.", dns.TypeOPT))
	chaos := dns.NewMsg("example.test.", dns.TypeA)
	chaos.Question[0].Header().Class = dns.ClassCHAOS
	check("CHAOS A", chaos)
}

func TestCacheMetaTypesDoNotShareAnswers(t *testing.T) {
	c, _ := newCache(10, false)
	anyQ := dns.NewMsg("example.test.", dns.TypeANY)
	c.put(anyQ, cacheTestAnswer(t, anyQ, "example.test. 300 IN HINFO \"RFC8482\" \"\""))
	if _, hit := c.get(anyQ); !hit {
		t.Fatal("ANY answer was not cached")
	}
	if got, _ := c.get(dns.NewMsg("example.test.", dns.TypeNXNAME)); got != nil {
		t.Fatalf("NXNAME question received the cached ANY answer: %v", got)
	}
}

func TestCacheNameCaseInsensitive(t *testing.T) {
	mixed := dns.NewMsg("ExAmPlE.TeSt.", dns.TypeA)
	lower := dns.NewMsg("example.test.", dns.TypeA)
	if key(mixed) != key(lower) {
		t.Fatalf("case variants use different keys: %q and %q", key(mixed), key(lower))
	}
	s := runtimeServer("127.0.0.1:0")
	s.cache.put(mixed, cacheTestAnswer(t, mixed, "ExAmPlE.TeSt. 300 IN A 192.0.2.1"))
	w := dnstest.NewTestRecorder()
	s.ServeDNS(context.Background(), w, lower)
	if err := w.Msg.Unpack(); err != nil {
		t.Fatal(err)
	}
	if len(w.Msg.Answer) != 1 {
		t.Fatalf("lowercase query missed the mixed-case entry: %v", w.Msg)
	}
	if got := w.Msg.Question[0].Header().Name; got != "example.test." {
		t.Errorf("response question = %q, want the client's spelling", got)
	}
}

// wireQuery unpacks a query from wire format, as the server receives it; the
// library cannot construct some meta-type questions directly.
func wireQuery(t *testing.T, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := dns.NewMsg(name, dns.TypeA)
	if err := m.Pack(); err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), m.Data...)
	binary.BigEndian.PutUint16(data[12+len(name)+1:], qtype)
	q := &dns.Msg{Data: data}
	if err := q.Unpack(); err != nil {
		t.Fatal(err)
	}
	if got := dns.RRToType(q.Question[0]); got != qtype {
		t.Fatalf("question type = %d, want %d", got, qtype)
	}
	return q
}

func TestCacheableQueryRejectsMetaTypes(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeNone, dns.TypeOPT, dns.TypeTKEY, dns.TypeTSIG, dns.TypeIXFR, dns.TypeAXFR, dns.TypeMAILB, dns.TypeMAILA} {
		if cacheableQuery(wireQuery(t, "example.test.", qtype)) {
			t.Errorf("type %d is cacheable", qtype)
		}
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeANY} {
		if !cacheableQuery(wireQuery(t, "example.test.", qtype)) {
			t.Errorf("type %d is no longer cacheable", qtype)
		}
	}
}
