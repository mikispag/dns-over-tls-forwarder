# dns-over-tls-forwarder
A simple DNS-over-TLS forwarding server with adaptive caching written in Go.

## Usage
```
  -a
    	the address to listen on. If only port is needed prefix with : (default ":53")
  -l
    	log file path
  -s
    	upstream DNS-over-TLS server (examples: one.one.one.one:853@1.1.1.1 or dns.google:853@8.8.8.8 (default "one.one.one.one:853@1.1.1.1")
  -v	verbose mode
  ```
## Credits

Thanks to [@empijei](https://github.com/empijei) for the great Go mentoring in design and style and several contributions.
