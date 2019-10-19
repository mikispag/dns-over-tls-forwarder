package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/mikispag/dns-over-tls-forwarder/proxy/internal/specialized/fuzz"
)

func main() {
	var out io.Writer
	fuzz.Printf = func(f string, d ...interface{}) {
		fmt.Fprintf(out, f, d...)
		fmt.Fprintln(out)
	}

	for _, v := range os.Args[1:] {
		fname := "./crashers_decoded/" + path.Base(v)
		f, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("cannot open output file: %q", fname)
		}
		out = io.MultiWriter(os.Stdout, f)
		fmt.Fprintln(out, v)
		buf, err := ioutil.ReadFile(v)
		if err != nil {
			os.Exit(1)
		}
		fuzz.Fuzz(buf)
		fmt.Fprintln(out)
	}
}
