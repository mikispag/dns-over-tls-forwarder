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
	printf("size: %d", size)
	c, err := specialized.NewCache(size)
	if err != nil {
		return 0
	}
	exp := make(map[string]string)
	for k, op := range tos {
		if op.op == put {
			// PUT
			c.Put(op.k, op.v)
			printf("put(%q,%q)", op.k, op.v)
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
		w, okk := exp[op.k]
		if !ok && !okk {
			// Double miss, we don't care
			printf("get(%q): double miss", op.k)
			continue
		}
		if !ok && okk {
			if c.Len() < c.Cap() {
				// Cache miss, map hit, cache is not full
				barf("get(%q): spurious miss", op.k)
			}
			// Cache miss, map hit, item was evicted
			printf("get(%q): evict miss", op.k)
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
		printf("get(%q): hit! %v", op.k, vv)
	}
	return r
}

func barf(f string, d ...interface{}) {
	panic(fmt.Sprintf(f, d...))
}

func printf(f string, d ...interface{}) {}
