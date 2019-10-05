# dns-over-tls-forwarder

[![Go Report](https://goreportcard.com/badge/github.com/mikispag/dns-over-tls-forwarder)](https://goreportcard.com/badge/github.com/mikispag/dns-over-tls-forwarder)

A simple DNS-over-TLS forwarding server with adaptive caching written in Go.

The server forwards to an user-specified list of upstream DNS-over-TLS servers (by defeault, to both CloudFlare `one.one.one.one:853@1.1.1.1` and Google `dns.google:853@8.8.8.8`) in parallel, returning and caching the first result received.

## Usage
```console
  -a address:port
    	the address:port to listen on. In order to listen on the loopback interface only, use `127.0.0.1:53`. To listen on any interface, use `:53` (default ":53")
  -l string
    	log file path
  -s string
    	comma-separated list of upstream servers (default "one.one.one.one:853@1.1.1.1,dns.google:853@8.8.8.8")
  -v	verbose mode
```
## Credits

Thanks to [@empijei](https://github.com/empijei) for the great Go mentoring in design and style and several contributions.
