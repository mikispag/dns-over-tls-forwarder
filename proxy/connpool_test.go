package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoolLimitsActiveConnections(t *testing.T) {
	var dials atomic.Int32
	p := newPool(1, func(context.Context) (net.Conn, error) {
		dials.Add(1)
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		return client, nil
	})
	t.Cleanup(p.shutdown)
	first, err := p.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan net.Conn, 1)
	go func() {
		c, _ := p.get(context.Background())
		result <- c
	}()
	select {
	case <-result:
		t.Fatalf("second checkout exceeded pool capacity: %d connections dialed", dials.Load())
	case <-time.After(30 * time.Millisecond):
	}
	p.put(first)
	select {
	case second := <-result:
		if second != first || dials.Load() != 1 {
			t.Fatalf("expected reuse of first connection; dials=%d", dials.Load())
		}
		p.put(second)
	case <-time.After(time.Second):
		t.Fatal("waiting checkout was not released")
	}
}

func TestPoolCheckoutCancellation(t *testing.T) {
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	p := newPool(1, func(context.Context) (net.Conn, error) { return client, nil })
	defer p.shutdown()
	if _, err := p.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.get(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("checkout error = %v, want deadline exceeded", err)
	}
}

func TestPoolShutdownCancelsDial(t *testing.T) {
	started := make(chan struct{})
	p := newPool(1, func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	defer p.shutdown()
	result := make(chan error, 1)
	go func() {
		_, err := p.get(context.Background())
		result <- err
	}()
	<-started
	p.shutdown()
	select {
	case err := <-result:
		if !errors.Is(err, errPoolClosed) {
			t.Fatalf("checkout error = %v, want closed pool", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel dialing")
	}
}

func TestPoolShutdownClosesAllConnections(t *testing.T) {
	var peers []net.Conn
	p := newPool(2, func(context.Context) (net.Conn, error) {
		client, peer := net.Pipe()
		peers = append(peers, peer)
		return client, nil
	})
	defer p.shutdown()
	first, err := p.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.put(first)
	p.shutdown()
	for _, peer := range peers {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Errorf("peer read = %v, want EOF", err)
		}
		_ = peer.Close()
	}
	if _, err := p.get(context.Background()); !errors.Is(err, errPoolClosed) {
		t.Fatalf("checkout after shutdown = %v", err)
	}
}

func TestPoolShutdownWakesWaiters(t *testing.T) {
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	p := newPool(1, func(context.Context) (net.Conn, error) { return client, nil })
	defer p.shutdown()
	if _, err := p.get(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := p.get(context.Background())
		result <- err
	}()
	p.shutdown()
	select {
	case err := <-result:
		if !errors.Is(err, errPoolClosed) {
			t.Fatalf("checkout error = %v, want closed pool", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not release waiting checkout")
	}
}

func TestPoolCancellationClosesLateDialResult(t *testing.T) {
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	started := make(chan struct{})
	p := newPool(1, func(ctx context.Context) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return client, nil
	})
	defer p.shutdown()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := p.get(ctx)
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("checkout error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("checkout did not return after cancellation")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late connection was not closed: %v", err)
	}
}

func TestPoolDiscardReleasesCapacity(t *testing.T) {
	var dials int
	p := newPool(1, func(context.Context) (net.Conn, error) {
		dials++
		if dials == 1 {
			return nil, errors.New("dial failed")
		}
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		return client, nil
	})
	defer p.shutdown()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := p.get(ctx); err == nil {
		t.Fatal("expected failed initial dial")
	}
	first, err := p.get(ctx)
	if err != nil {
		t.Fatalf("failed dial did not release capacity: %v", err)
	}
	p.discard(first)
	second, err := p.get(ctx)
	if err != nil || second == first || dials != 3 {
		t.Fatalf("discard did not replace connection: dials=%d, err=%v", dials, err)
	}
	p.put(second)
}

func TestPoolReuseDoesNotProbeConnection(t *testing.T) {
	client, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	p := newPool(1, func(context.Context) (net.Conn, error) { return client, nil })
	defer p.shutdown()
	c, err := p.get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.put(c)
	go func() { _, _ = peer.Write([]byte{42}) }()
	reused, err := p.get(context.Background())
	if err != nil || reused != c {
		t.Fatalf("expected connection reuse: %v", err)
	}
	_ = reused.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err := reused.Read(data[:]); err != nil || data[0] != 42 {
		t.Fatalf("checkout consumed connection bytes: data=%v, err=%v", data, err)
	}
}
