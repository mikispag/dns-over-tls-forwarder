package fuzz

import (
	"encoding/binary"
	"fmt"

	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
)

const (
	get = false
	put = true
)

type testOp struct {
	op   bool
	k, v string
}

func translate(b []byte) (tos []testOp, size, r int) {
	if len(b) > 1000000 {
		// 1M operations are enough.
		// Fuzzing with more will cause weird OOM crashes.
		return
	}
	if len(b) < 11 {
		// Need more to fuzz with
		return
	}
	size = int(binary.BigEndian.Uint16(b[:2]))
	b = b[4:]
	for len(b) > 9 {
		tos = append(tos, testOp{
			op: b[0]%2 == 0,
			k:  string(b[1:5]),
			v:  string(b[5:9]),
		})
		b = b[9:]
	}
	return tos, size, len(tos)
}

func Fuzz(b []byte) int {
	tos, size, r := translate(b)
	if r <= 0 {
		return r
	}
	Printf("size: %d", size)
	c, err := specialized.NewCache(size, true)
	if err != nil {
		return 0
	}
	var hits, misses uint
	exp := make(map[string]string)
	for k, op := range tos {
		if op.op == put {
			// PUT
			c.Put(op.k, op.v)
			Printf("put(%q,%q)", op.k, op.v)
			exp[op.k] = op.v
			if c.Len() > size {
				barf("cache outgrew expected limit")
			}
			if k < size && c.Len() < len(exp) {
				barf("cache didn't grow as map")
			}
			continue
		}
		// GET
		v, ok := c.Get(op.k)
		if ok {
			hits++
		} else {
			misses++
		}
		w, okk := exp[op.k]
		if !ok && !okk {
			// Double miss, we don't care
			Printf("get(%q): double miss", op.k)
			continue
		}
		if !ok && okk {
			if c.Len() < c.Cap() {
				// Cache miss, map hit, cache is not full
				barf("get(%q): spurious miss", op.k)
			}
			// Cache miss, map hit, item was evicted
			Printf("get(%q): evict miss", op.k)
			continue
		}
		// Cache hit
		vv := v.(string)
		if !okk {
			// Cache hit but entry is not in map
			barf("get(%q): spurious hit %v", op.k, vv)
		}
		// Double hit
		if ok && okk && w != vv {
			// Double hit, but different values
			barf("got %s want %s", vv, w)
		}
		Printf("get(%q): hit! %v", op.k, vv)
	}
	if size <= 0 {
		return r
	}
	m := c.Metrics()
	if m.Hit() != hits {
		barf("hits: got %d want %d", m.Hit(), hits)
	}
	if m.Miss != misses {
		barf("misses: got %d want %d", m.Miss, misses)
	}
	return r
}

func barf(f string, d ...interface{}) { panic(fmt.Sprintf(f, d...)) }

// Printf is the printer for the fuzzer. It defaults to discarding.
var Printf = func(f string, d ...interface{}) {}
