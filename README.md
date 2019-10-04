# dns-over-tls-forwarder

[![Go Report](https://goreportcard.com/badge/github.com/mikispag/dns-over-tls-forwarder)](https://goreportcard.com/badge/github.com/mikispag/dns-over-tls-forwarder)

A simple DNS-over-TLS forwarding server with adaptive caching written in Go.

The server forwards to both CloudFlare DNS-over-TLS server (`one.one.one.one:853@1.1.1.1`) and Google DNS-over-TLS server (`dns.google:853@8.8.8.8`) in parallel, returning and caching the first result received.

## Usage
```
  -a
    	the address to listen on. If only port is needed prefix with : (default ":53")
  -l
    	log file path
  -v	verbose mode
  ```
## Credits

Thanks to [@empijei](https://github.com/empijei) for the great Go mentoring in design and style and several contributions.
