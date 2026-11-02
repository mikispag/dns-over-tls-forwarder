package proxy

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"
)

// maxTCPClients bounds concurrent TCP connections so a flood cannot exhaust
// file descriptors needed by UDP clients and upstream connections. Further
// connections wait in the kernel backlog.
const maxTCPClients = 256

// trackedListener closes accepted TCP sockets and waits for their readers to
// exit before the DNS library waits for handlers. The library closes each
// accepted connection when its reader has finished starting handlers.
type trackedListener struct {
	net.Listener
	slots     chan struct{}
	closing   chan struct{}
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

func newTrackedListener(l net.Listener, maxConns int) net.Listener {
	return &trackedListener{
		Listener:  l,
		slots:     make(chan struct{}, maxConns),
		closing:   make(chan struct{}),
		conns:     make(map[*trackedConn]struct{}),
		done:      make(chan struct{}),
		acceptErr: make(chan error, 1),
	}
}

// Accept retries transient failures itself: the DNS library retries every
// Accept error immediately, which would spin, and Run treats a reported
// error as fatal.
func (l *trackedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.closing:
		return nil, net.ErrClosed
	}
	var delay time.Duration
	for {
		c, err := l.Listener.Accept()
		if err == nil {
			return l.track(c)
		}
		l.mu.Lock()
		closed := l.closed
		l.mu.Unlock()
		if !closed && transientAcceptError(err) {
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			select {
			case <-time.After(delay):
				continue
			case <-l.closing:
			}
		} else if !closed {
			select {
			case l.acceptErr <- err:
			default:
			}
		}
		<-l.slots
		return nil, err
	}
}

func (l *trackedListener) track(c net.Conn) (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		_ = c.Close()
		<-l.slots
		return nil, net.ErrClosed
	}
	tc := &trackedConn{Conn: c, listener: l}
	l.conns[tc] = struct{}{}
	l.readers.Add(1)
	return tc, nil
}

// transientAcceptError reports failures that clear up on their own, such as
// descriptor exhaustion or a client resetting before the handshake completed.
func transientAcceptError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	for _, errno := range transientAcceptErrnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// transientAcceptErrnos are descriptor and memory exhaustion, plus network
// errors that Linux reports from the accepted socket and accept(2) says to
// retry. Go retries EINTR and ECONNABORTED itself on Unix.
var transientAcceptErrnos = []syscall.Errno{
	syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
	syscall.ECONNABORTED, syscall.ECONNRESET, syscall.ENETDOWN, syscall.ENETUNREACH,
	syscall.EHOSTDOWN, syscall.EHOSTUNREACH, syscall.EPROTO, syscall.ENOPROTOOPT, syscall.EOPNOTSUPP,
}

func (l *trackedListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		<-l.done
		return l.closeErr
	}
	l.closed = true
	close(l.closing)
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
		<-c.listener.slots
	})
	return err
}
