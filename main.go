package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/gologme/log"
	"github.com/mikispag/dns-over-tls-forwarder/proxy"
)

const (
	// Absolute maximum TTL to cache, set to 2^31 - 1. See: https://tools.ietf.org/html/rfc1034.
	absoluteMaxTTL = 2147483647
)

var (
	debugLog        = flag.Bool("d", false, "print debug log messages")
	upstreamServers = flag.String("s", "one.one.one.one:853@1.1.1.1,dns.google:853@8.8.8.8", "comma-separated list of upstream servers")
	logPath         = flag.String("l", "", "log file path")
	minTTL          = flag.Int("minTTL", 0, "minimum answer TTL in seconds; zero preserves upstream TTLs")
	maxStale        = flag.Duration("maxStale", time.Hour, "maximum age after expiry for eligible stale answers; zero disables stale serving")
	evictMetrics    = flag.Bool("em", false, "collect metrics on evictions")
	addr            = flag.String("a", "127.0.0.1:53", "`address:port` to listen on over UDP and TCP; use a LAN address for network clients")
	metricsPort     = flag.Int("metrics", 0, "port for metrics and JSON diagnostics on 127.0.0.1; zero disables HTTP")
)

func main() {
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if *minTTL < 0 || *minTTL > absoluteMaxTTL {
		return fmt.Errorf("minTTL must be between 0 and %d", absoluteMaxTTL)
	}
	if *maxStale < 0 {
		return errors.New("maxStale must not be negative")
	}
	if *metricsPort < 0 || *metricsPort > 65535 {
		return errors.New("metrics port must be between 0 and 65535")
	}
	upstreams := strings.Split(*upstreamServers, ",")
	if err := proxy.ValidateUpstreams(upstreams...); err != nil {
		return err
	}

	var output io.Writer = os.Stdout
	if *logPath != "" {
		lf, err := os.OpenFile(*logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		defer func() { _ = lf.Close() }()
		output = io.MultiWriter(os.Stdout, lf)
	}
	logger := log.New(output, "", log.LstdFlags)
	for _, level := range []string{"info", "warn", "error"} {
		logger.EnableLevel(level)
	}
	if *debugLog {
		logger.EnableLevel("debug")
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		logger.Infof("%s v%s", path.Base(bi.Path), bi.Main.Version)
	}

	server := proxy.NewServer(nil, logger, 0, *evictMetrics, *minTTL, *addr, upstreams...)
	server.SetMaxStale(*maxStale)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var httpServer *http.Server
	var httpResult chan error
	if *metricsPort != 0 {
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(*metricsPort)))
		if err != nil {
			return fmt.Errorf("metrics listener: %w", err)
		}
		httpMux := http.NewServeMux()
		httpMux.Handle("/debug/server/", server.DebugHandler())
		httpMux.Handle("/metrics", server.PrometheusHandler())
		httpServer = &http.Server{
			Handler: httpMux, ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		}
		defer func() { _ = httpServer.Close() }()
		httpResult = make(chan error, 1)
		go func() {
			err := httpServer.Serve(listener)
			if errors.Is(err, http.ErrServerClosed) {
				err = nil
			}
			httpResult <- err
			cancel()
		}()
	}

	err := server.Run(ctx)
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	if httpServer != nil {
		shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		err = errors.Join(err, httpServer.Shutdown(shutdownCtx), <-httpResult)
	}
	return err
}
