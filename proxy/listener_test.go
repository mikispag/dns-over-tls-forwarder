package proxy

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestTrackedListenerCloseWaitsForReaders(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newTrackedListener(raw, maxTCPClients)
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	t.Cleanup(func() { _ = conn.Close(); _ = l.Close() })
	readDone := make(chan struct{})
	go func() {
		_, _ = conn.Read(make([]byte, 1))
		close(readDone)
		<-release
		_ = conn.Close()
	}()
	closed := make(chan error, 1)
	go func() { closed <- l.Close() }()
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("listener close did not interrupt client reader")
	}
	select {
	case err := <-closed:
		t.Fatalf("listener close returned before reader exit: %v", err)
	default:
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("client read = %v, want EOF", err)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener close did not finish after reader exit")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

type delayedAcceptListener struct {
	net.Listener
	accepted chan struct{}
	release  chan struct{}
}

func (l *delayedAcceptListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	close(l.accepted)
	<-l.release
	return c, err
}

func TestTrackedListenerRejectsLateAccept(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	delayed := &delayedAcceptListener{Listener: raw, accepted: make(chan struct{}), release: make(chan struct{})}
	l := newTrackedListener(delayed, maxTCPClients)
	defer func() { _ = l.Close() }()
	accepted := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- err
	}()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	<-delayed.accepted
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	close(delayed.release)
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("late accept = %v, want closed listener", err)
		}
	case <-time.After(time.Second):
		t.Fatal("accept did not return after shutdown")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late connection was not closed: %v", err)
	}
}

// failingListener returns the queued errors before accepting normally.
type failingListener struct {
	net.Listener
	errs []error
}

func (l *failingListener) Accept() (net.Conn, error) {
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		return nil, err
	}
	return l.Listener.Accept()
}

func TestTrackedListenerRetriesTransientErrors(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	failing := &failingListener{Listener: raw, errs: []error{
		&net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.EMFILE)},
		&net.OpError{Op: "accept", Err: os.NewSyscallError("accept", syscall.ECONNABORTED)},
	}}
	l := newTrackedListener(failing, maxTCPClients).(*trackedListener)
	defer func() { _ = l.Close() }()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("accept after transient errors: %v", err)
	}
	_ = conn.Close()
	select {
	case err := <-l.acceptErr:
		t.Fatalf("transient error reported as fatal: %v", err)
	default:
	}
}

func TestTrackedListenerBoundsClients(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := newTrackedListener(raw, 1)
	defer func() { _ = l.Close() }()
	for range 2 {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
	}
	first, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	second := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		second <- c
	}()
	select {
	case <-second:
		t.Fatal("accepted a client beyond the limit")
	case <-time.After(50 * time.Millisecond):
	}
	_ = first.Close()
	select {
	case c := <-second:
		if c == nil {
			t.Fatal("accept failed after a slot was released")
		}
		_ = c.Close()
	case <-time.After(time.Second):
		t.Fatal("closing a client did not release its slot")
	}
}
