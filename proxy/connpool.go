package proxy

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type connector func() (net.Conn, error)

type pool struct {
	addr string
	c    connector

	mu     sync.RWMutex
	closed bool
	buf    chan net.Conn
}

func newPool(size int, c connector) *pool {
	return newPoolWithAddr(size, "", c)
}

func newPoolWithAddr(size int, addr string, c connector) *pool {
	return &pool{
		addr: addr,
		buf:  make(chan net.Conn, size),
		c:    c,
	}
}

func isConnAlive(c net.Conn) bool {
	if c == nil {
		return false
	}
	// Try a short deadline 1-byte read to probe connection health
	err := c.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	if err != nil {
		// If deadlines are not supported on this net.Conn, assume alive
		return true
	}
	var b [1]byte
	n, readErr := c.Read(b[:])
	_ = c.SetReadDeadline(time.Time{})
	if n > 0 {
		// Unexpected unread data on idle connection
		return false
	}
	if readErr != nil {
		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			return true
		}
		if errors.Is(readErr, os.ErrDeadlineExceeded) {
			return true
		}
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, net.ErrClosed) {
			return false
		}
		return false
	}
	return true
}

func (p *pool) get() (net.Conn, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, errors.New("pool is shut down")
	}

	for {
		select {
		case c := <-p.buf:
			if isConnAlive(c) {
				return c, nil
			}
			_ = c.Close()
			continue
		default:
			return p.c()
		}
	}
}

func (p *pool) put(c net.Conn) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || c == nil {
		if c != nil {
			_ = c.Close()
		}
		return
	}

	select {
	case p.buf <- c:
	default:
		_ = c.Close()
	}
}

func (p *pool) shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true

	close(p.buf)
	for c := range p.buf {
		_ = c.Close()
	}
}
