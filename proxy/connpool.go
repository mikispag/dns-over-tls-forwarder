package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
)

type connector func(context.Context) (net.Conn, error)

var errPoolClosed = errors.New("pool is shut down")

type pool struct {
	addr string
	c    connector

	mu      sync.Mutex
	closed  bool
	size    int
	dialing int
	conns   map[net.Conn]bool // true while checked out
	idle    []net.Conn
	changed chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
}

func newPool(size int, c connector) *pool {
	return newPoolWithAddr(size, "", c)
}

func newPoolWithAddr(size int, addr string, c connector) *pool {
	ctx, cancel := context.WithCancel(context.Background())
	return &pool{
		addr:    addr,
		c:       c,
		size:    size,
		conns:   make(map[net.Conn]bool),
		changed: make(chan struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (p *pool) notifyLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *pool) get(ctx context.Context) (net.Conn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errPoolClosed
		}
		if n := len(p.idle); n > 0 {
			c := p.idle[n-1]
			p.idle = p.idle[:n-1]
			p.conns[c] = true
			p.mu.Unlock()
			return c, nil
		}
		if len(p.conns)+p.dialing < p.size {
			p.dialing++
			p.mu.Unlock()
			dialCtx, cancel := context.WithCancel(ctx)
			stop := context.AfterFunc(p.ctx, cancel)
			c, err := p.c(dialCtx)
			stop()
			cancel()
			p.mu.Lock()
			p.dialing--
			if p.closed {
				err = errPoolClosed
			} else if ctx.Err() != nil {
				err = ctx.Err()
			}
			if err == nil {
				p.conns[c] = true
			}
			p.notifyLocked()
			p.mu.Unlock()
			if err != nil && c != nil {
				_ = c.Close()
				c = nil
			}
			return c, err
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-changed:
		}
	}
}

func (p *pool) put(c net.Conn) {
	if c == nil {
		return
	}
	p.mu.Lock()
	active, ok := p.conns[c]
	if ok && active {
		p.conns[c] = false
		p.idle = append(p.idle, c)
		p.notifyLocked()
	}
	p.mu.Unlock()
	if !ok {
		_ = c.Close()
	}
}

func (p *pool) discard(c net.Conn) {
	p.mu.Lock()
	active, ok := p.conns[c]
	if ok {
		delete(p.conns, c)
		if !active {
			for i, idle := range p.idle {
				if idle == c {
					p.idle = append(p.idle[:i], p.idle[i+1:]...)
					break
				}
			}
		}
		p.notifyLocked()
	}
	p.mu.Unlock()
	if ok {
		_ = c.Close()
	}
}

func (p *pool) shutdown() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	conns := p.conns
	p.conns = nil
	p.idle = nil
	p.notifyLocked()
	p.mu.Unlock()
	p.cancel()
	for c := range conns {
		_ = c.Close()
	}
}
