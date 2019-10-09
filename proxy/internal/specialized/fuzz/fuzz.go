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
	c, err := specialized.NewCache(size)
	if err != nil {
		return 0
	}
	exp := make(map[string]string)
	for k, op := range tos {
		if op.op == get {
			v, ok := c.Get(op.k)
			printf("get %q", op.k)
			w, okk := exp[op.k]
			if ok && okk {
				vv := v.(string)
				if w != vv {
					barf("got %s want %s", vv, w)
				}
			}
			continue
		}
		c.Put(op.k, op.v)
		printf("put %q", op.k)
		exp[op.k] = op.v
		if len(exp) > size {
			for k := range exp {
				delete(exp, k)
				break
			}
		}
		if c.Len() > size {
			barf("cache outgrew expected limit")
		}
		if k < size && c.Len() < len(exp) {
			barf("cache didn't grow as map")
		}
	}
	return r
}

func barf(f string, d ...interface{}) {
	panic(fmt.Sprintf(f, d...))
}

func printf(f string, d ...interface{}) {}
