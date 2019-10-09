package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized"
)

func main() {
	buf, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	Fuzz(buf)
}

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
	fmt.Printf("size: %d\n", size)
	for _, op := range tos {
		if op.op == get {
			fmt.Printf("get %s", op.k)
			v, ok := c.Get(op.k)
			// TODO use these values.
			_, _ = v, ok
			continue
		}
		c.Put(op.k, op.v)
		fmt.Printf("put %s", op.k)
	}
	return r
}
