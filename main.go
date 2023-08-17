package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	_ "net/http/pprof"
	"os"
	"path"
	"runtime/debug"
	"strings"

	"github.com/gologme/log"
	"github.com/miekg/dns"
	"github.com/mikispag/dns-over-tls-forwarder/proxy"
)

var (
	upstreamServers = flag.String("s", "one.one.one.one:853@1.1.1.1,dns.google:853@8.8.8.8", "comma-separated list of upstream servers")
	logPath         = flag.String("l", "", "log file path")
	isLogVerbose    = flag.Bool("v", false, "verbose mode")
	evictMetrics    = flag.Bool("em", false, "collect metrics on evictions")
	addr            = flag.String("a", ":53", "the `address:port` to listen on. In order to listen on the loopback interface only, use `127.0.0.1:53`. To listen on any interface, use `:53`")
	ppr             = flag.Int("pprof", 0, "The port to use for pprof debugging. If set to 0 (default) pprof will not be started.")
)

func main() {
	flag.Parse()

	if *logPath != "" {
		lf, err := os.OpenFile(*logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			log.Errorf("Unable to open log file for writing: %s", err)
		} else {
			log.SetOutput(io.MultiWriter(lf, os.Stdout))
		}
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		log.Infof("%s v%s", path.Base(bi.Path), bi.Main.Version)
	}
	logger := log.New(os.Stdout, "", log.Flags())
	mux := dns.NewServeMux()
	// Run the server with a default cache size and the specified upstream servers.
	server := proxy.NewServer(mux, logger, 0, *evictMetrics, *addr, strings.Split(*upstreamServers, ",")...)

	if *ppr != 0 {
		mux := http.NewServeMux()
		mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
		mux.Handle("/debug/server/", server.DebugHandler())
		go func() { log.Error(http.ListenAndServe(fmt.Sprintf("localhost:%d", *ppr), mux)) }()
	}
	mux.HandleFunc(".", server.ServeDNS)

	sigs := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-sigs
		cancel()
		server.Shutdown(ctx)
	}()

	log.Fatal(server.Run(ctx))
}
