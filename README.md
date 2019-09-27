# dns-over-tls-forwarder
A simple DNS-over-TLS forwarding server with adaptive caching written in Go.

## Usage
```
  -l string
    	log file path
  -s string
    	upstream DNS-over-TLS server (examples: one.one.one.one:853@1.1.1.1 or dns.google:853@8.8.8.8 (default "one.one.one.one:853@1.1.1.1")
  -v	verbose mode
  ```
## Credits

Thanks to [@empijei](https://github.com/empijei) for the great Go mentoring in style and with channels.
