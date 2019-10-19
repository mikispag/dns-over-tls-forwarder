# dns-over-tls-forwarder

[![Go Report](https://goreportcard.com/badge/github.com/mikispag/dns-over-tls-forwarder)](https://goreportcard.com/badge/github.com/mikispag/dns-over-tls-forwarder)

A simple, fast DNS-over-TLS forwarding server with hybrid LRU/MFA caching written in Go.

The server forwards to an user-specified list of upstream DNS-over-TLS servers in parallel, returning and caching the first result received.

## Upstream servers

The default list of upstream servers is:
  - **CloudFlare** `one.one.one.one:853@1.1.1.1`
  - **Google** `dns.google:853@8.8.8.8`

Other popular upstream servers known to support DNS-over-TLS are:
  - **Quad9 (filters malware)** `dns.quad9.net:853@9.9.9.9`
  - **Quad9 (no filtering)** `dns10.quad9.net:853@9.9.9.10`

A custom comma-separated list of upstream servers can be specified with the `-s` command line flag.

## Usage
```console
  -a address:port
        the address:port to listen on. In order to listen on the loopback interface only, use `127.0.0.1:53`. To listen on any interface, use `:53` (default ":53")
  -em
        collect metrics on evictions
  -l string
        log file path
  -pprof int
        The port to use for pprof debugging. If set to 0 (default) pprof will not be started.
  -s string
        comma-separated list of upstream servers (default "one.one.one.one:853@1.1.1.1,dns.google:853@8.8.8.8")
  -v    verbose mode
```
## Credits

Thanks to [@empijei](https://github.com/empijei) for the great Go mentoring in design and style and several contributions.
