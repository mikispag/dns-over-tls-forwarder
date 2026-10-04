package proxy

import (
	"net"
	"sync"
)

// trackedListener closes accepted TCP sockets and waits for their readers to
// exit before the DNS library waits for handlers. The library closes each
// accepted connection when its reader has finished starting handlers.
type trackedListener struct {
	net.Listener
	mu        sync.Mutex
	closed    bool
	conns     map[*trackedConn]struct{}
	readers   sync.WaitGroup
	done      chan struct{}
	closeErr  error
	acceptErr chan error
}

type trackedConn struct {
	net.Conn
	listener *trackedListener
	once     sync.Once
}

func newTrackedListener(l net.Listener) net.Listener {
	return &trackedListener{Listener: l, conns: make(map[*trackedConn]struct{}), done: make(chan struct{}), acceptErr: make(chan error, 1)}
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		l.mu.Lock()
		closed := l.closed
		l.mu.Unlock()
		if !closed {
			select {
			case l.acceptErr <- err:
			default:
			}
		}
		return nil, err
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	tc := &trackedConn{Conn: c, listener: l}
	l.conns[tc] = struct{}{}
	l.readers.Add(1)
	l.mu.Unlock()
	return tc, nil
}

func (l *trackedListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		<-l.done
		return l.closeErr
	}
	l.closed = true
	conns := make([]net.Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c.Conn)
	}
	l.mu.Unlock()
	l.closeErr = l.Listener.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	l.readers.Wait()
	close(l.done)
	return l.closeErr
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.listener.mu.Lock()
		delete(c.listener.conns, c)
		c.listener.mu.Unlock()
		c.listener.readers.Done()
	})
	return err
}
