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
	if len(b) < 5 {
		// Need more to fuzz with
		return
	}
	size = int(binary.BigEndian.Uint16(b[:2]))
	b = b[4:]
	for len(b) > 3 {
		tos = append(tos, testOp{
			op: b[0]%2 == 0,
			k:  string(b[1]),
			v:  string(b[2]),
		})
		b = b[3:]
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
	for _, op := range tos {
		if op.op == get {
			v, ok := c.Get(op.k)
			// TODO use these values.
			_, _ = v, ok
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
		exp[op.k] = op.v
		if len(exp) > 100000 {
			for k := range exp {
				delete(exp, k)
				break
			}
		}
	}
	return r
}

func barf(f string, d ...interface{}) {
	panic(fmt.Sprintf(f, d...))
}

func printf(f string, d ...interface{}) {
	fmt.Printf(f, d...)
}
