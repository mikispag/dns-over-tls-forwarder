package proxy

import (
	"errors"
	"net"
	"sync"
)

type connector func() (net.Conn, error)

type pool struct {
	c connector

	mu     sync.RWMutex
	closed bool
	buf    chan net.Conn
}

func newPool(size int, c connector) *pool {
	return &pool{
		buf: make(chan net.Conn, size),
		c:   c,
	}
}

func (p *pool) get() (net.Conn, error) {
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

func (p *pool) put(c net.Conn) {
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
