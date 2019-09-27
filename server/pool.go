package server

import (
	"github.com/miekg/dns"
)

type connector func() (*dns.Conn, error)

type pool struct {
	buf  chan *dns.Conn
	c    connector
	done chan struct{}
}

func newPool(size int, c connector) *pool {
	return &pool{
		buf:  make(chan *dns.Conn, size),
		c:    c,
		done: make(chan struct{}),
	}
}

func (p pool) get() (*dns.Conn, error) {
	select {
	case c := <-p.buf:
		return c, nil
	default:
		return p.c()
	}
}

func (p pool) put(c *dns.Conn) {
	select {
	case p.buf <- c:
	default:
		c.Close()
	}
}

// shutdown is not safe for concurrent use with put
func (p pool) shutdown() {
	close(p.buf)
	for c := range p.buf {
		c.Close()
	}
}
