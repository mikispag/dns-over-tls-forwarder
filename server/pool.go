package server

import (
	"errors"
	"sync"

	"github.com/miekg/dns"
)

type connector func() (*dns.Conn, error)

type pool struct {
	c connector

	mu     sync.RWMutex
	closed bool
	buf    chan *dns.Conn
}

func newPool(size int, c connector) *pool {
	return &pool{
		buf: make(chan *dns.Conn, size),
		c:   c,
	}
}

func (p *pool) get() (*dns.Conn, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, errors.New("pool is shut down")
	}

	select {
	case c := <-p.buf:
		return c, nil
	default:
		return p.c()
	}
}

func (p *pool) put(c *dns.Conn) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return
	}

	select {
	case p.buf <- c:
	default:
		c.Close()
	}
}

func (p *pool) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true

	close(p.buf)
	for c := range p.buf {
		c.Close()
	}
}
