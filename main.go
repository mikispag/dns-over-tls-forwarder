package main

import (
	"context"
	"flag"
	"io"
	"os"

	"github.com/mikispag/dns-over-tls-forwarder/server"
	log "github.com/sirupsen/logrus"
)

const version = "1.0.0"

var (
	upstreamServer = flag.String("s", "one.one.one.one:853@1.1.1.1", "upstream DNS-over-TLS server (examples: one.one.one.one:853@1.1.1.1 or dns.google:853@8.8.8.8")
	logPath        = flag.String("l", "", "log file path")
	isLogVerbose   = flag.Bool("v", false, "verbose mode")
	addr           = flag.String("a", ":53", "the address to listen on. If only port is needed prefix with `:`")
)

func main() {
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	log.SetLevel(log.InfoLevel)
	if *isLogVerbose {
		log.SetLevel(log.DebugLevel)
	}

	if *logPath != "" {
		lf, err := os.OpenFile(*logPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			log.Errorf("Unable to open log file for writing: %s", err)
		} else {
			log.SetOutput(io.MultiWriter(lf, os.Stdout))
		}
	}

	log.Infof("DNS-over-TLS-Forwarder version %s", version)

	sigs := make(chan os.Signal, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-sigs
		cancel()
	}()
	server := server.New(*upstreamServer)
	log.Fatal(server.Run(ctx, *addr))
}
