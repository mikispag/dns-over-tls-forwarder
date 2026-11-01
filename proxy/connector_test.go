package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedTLS returns a server certificate for name and a pool trusting it.
func selfSignedTLS(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func TestConnectorResumesTLSSessions(t *testing.T) {
	const serverName = "resolver.test"
	cert, roots := selfSignedTLS(t, serverName)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			// Complete the handshake and send a byte so the client also
			// reads the session ticket that follows it.
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte{1})
				_, _ = c.Read(make([]byte, 1))
			}()
		}
	}()

	s := runtimeServer("127.0.0.1:0")
	s.dial = func(ctx context.Context, addr string, cfg *tls.Config) (net.Conn, error) {
		// The clone shares the connector's session cache.
		trusted := cfg.Clone()
		trusted.RootCAs = roots
		d := tls.Dialer{Config: trusted}
		return d.DialContext(ctx, "tcp", addr)
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	connect := s.connector(serverName + ":" + port + "@127.0.0.1")
	for i, wantResumed := range []bool{false, true} {
		c, err := connect(context.Background())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if _, err := c.Read(make([]byte, 1)); err != nil {
			t.Fatalf("dial %d: read: %v", i, err)
		}
		if got := c.(*tls.Conn).ConnectionState().DidResume; got != wantResumed {
			t.Errorf("dial %d: resumed = %v, want %v", i, got, wantResumed)
		}
		_ = c.Close()
	}
}
