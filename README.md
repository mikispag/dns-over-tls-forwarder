# dns-over-tls-forwarder

[![CI](https://github.com/mikispag/dns-over-tls-forwarder/actions/workflows/ci.yml/badge.svg)](https://github.com/mikispag/dns-over-tls-forwarder/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mikispag/dns-over-tls-forwarder.svg)](https://pkg.go.dev/github.com/mikispag/dns-over-tls-forwarder)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mikispag/dns-over-tls-forwarder)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Give ordinary DNS clients an encrypted path to upstream resolvers.**

`dns-over-tls-forwarder` accepts DNS over UDP and TCP, caches answers, and forwards cache misses over authenticated TLS 1.3. Run it on a workstation or a trusted gateway so applications get encrypted DNS without speaking DNS over TLS themselves.

```text
Applications ── ordinary DNS over UDP/TCP ──► dns-over-tls-forwarder
                                               ├── local cache
                                               └── DNS over TLS ──► upstream resolvers
```

## Try it locally

Requires **Go 1.27 or newer**, system CA certificates, and outbound TCP to your upstreams (normally port 853).

```sh
git clone https://github.com/mikispag/dns-over-tls-forwarder.git
cd dns-over-tls-forwarder
go build -o dns-over-tls-forwarder .
./dns-over-tls-forwarder -a 127.0.0.1:5353 -metrics 9100
```

In another terminal:

```sh
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com A +tcp
curl http://localhost:9100/metrics
```

Both queries should return an answer, and repeating one increases `dns_cache_hits_total`. Your system resolver is untouched; to use the forwarder for all lookups, bind it to port 53 ([Running with systemd](#running-with-systemd)) and point your operating system or router at it.

To install the binary instead: `go install github.com/mikispag/dns-over-tls-forwarder@latest`.

## How it works

- **Authenticated upstreams.** Connections require TLS 1.3 and verify the resolver's certificate against its hostname using the system trust store. Reconnects resume TLS sessions.
- **Racing.** Each cache miss goes to every upstream. The first `NOERROR` or `NXDOMAIN` wins; other responses are used only if neither arrives. This is a race, not failover or consensus.
- **Connection reuse.** Each upstream keeps up to two TLS connections. Slower upstreams finish their exchanges in the background, so their connections stay warm, and a connection the resolver closed while idle is retried transparently. Identical concurrent queries share one lookup, with a 10-second deadline.
- **Caching.** 65,536 entries, split between least-recently-used and most-frequently-accessed stores. Positive answers and SOA-bearing negative answers are cached; responses over 4 KiB are served but not cached. Expired answers can be served briefly while a refresh runs.
- **Privacy and EDNS.** Outbound queries drop client subnet (ECS) and other per-hop options such as cookies, and are padded to 128-byte blocks. Upstream padding never reaches clients or the cache, and clients receive EDNS only if they sent it. Cache keys ignore name case and separate the `DO`, `CD`, `RD`, and `AD` flags; queries with other EDNS options bypass the cache.
- **UDP sizing.** UDP replies are capped at the client's limit or 1232 bytes, whichever is smaller. Larger answers set `TC`, and the client retries over TCP.

The forwarder does not validate DNSSEC itself. The hop from clients is plain DNS, and each upstream sees the queries sent to it: TLS hides queries from the network, not from the resolver.

## Choosing upstreams

Pass a comma-separated list, without spaces, to `-s`:

```text
TLS-hostname:port@IP-address
```

The hostname is used for SNI and certificate verification, and the IP address for the connection, so no other resolver is needed to bootstrap.

| Resolver | Value for `-s` | Documentation |
| --- | --- | --- |
| Cloudflare | `one.one.one.one:853@1.1.1.1` | [DNS over TLS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/) |
| Google Public DNS | `dns.google:853@8.8.8.8` | [DNS over TLS](https://developers.google.com/speed/public-dns/docs/dns-over-tls) |
| Quad9 with threat blocking | `dns.quad9.net:853@9.9.9.9` | [Service addresses](https://docs.quad9.net/services/) |

Cloudflare and Google are the defaults. To use only Quad9:

```sh
./dns-over-tls-forwarder -a 127.0.0.1:5353 -s dns.quad9.net:853@9.9.9.9
```

Combine upstreams with the same filtering policy: with one blocking and one unfiltered resolver, the answer depends on which responds first. IPv6 addresses work with or without brackets, as in `dns.google:853@[2001:4860:4860::8888]`. An entry without `@` is resolved through the system resolver, which must not be this forwarder. Invalid entries fail startup.

## Command line reference

| Flag | Default | Behavior |
| --- | --- | --- |
| `-a` | `127.0.0.1:53` | UDP and TCP listen address. Use a LAN address to serve network clients. |
| `-s` | `one.one.one.one:853@1.1.1.1,dns.google:853@8.8.8.8` | Upstreams, comma-separated. |
| `-minTTL` | `0` | Raise shorter TTLs, including zero, in every record of a positive answer. Negative answers are unaffected. At most 2,147,483,647 seconds. |
| `-maxStale` | `1h` | How long after expiry a positive answer may be served stale, as a Go duration; `0` disables. |
| `-metrics` | `0` | Serve metrics and diagnostics on `127.0.0.1:<port>`; `0` disables. |
| `-em` | `false` | Track recently evicted cache entries for diagnostics, using extra memory. |
| `-d` | `false` | Debug logging, including query names. |
| `-l` | empty | Also append logs to this file; startup fails if it is not writable. |

`-h` prints the same reference. The CLI cache size is fixed; embedders pass a size to `proxy.NewServer`, where a negative size disables caching.

## Running with systemd

The [service unit](debian/dns-over-tls-forwarder.service) runs as a dynamic user holding only `CAP_NET_BIND_SERVICE`, under systemd sandboxing and a system call filter. It orders itself before `nss-lookup.target` and listens on loopback. To install it with metrics enabled:

```sh
sudo install -m 0755 dns-over-tls-forwarder /usr/local/bin/dns-over-tls-forwarder
sudo install -m 0644 debian/dns-over-tls-forwarder.service /etc/systemd/system/dns-over-tls-forwarder.service
sudo mkdir -p /etc/systemd/system/dns-over-tls-forwarder.service.d
sudo tee /etc/systemd/system/dns-over-tls-forwarder.service.d/local.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/dns-over-tls-forwarder -a 127.0.0.1:53 -metrics 9100
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now dns-over-tls-forwarder
```

Check it before changing your system DNS settings:

```sh
systemctl status dns-over-tls-forwarder
dig @127.0.0.1 example.com A
curl http://localhost:9100/metrics
```

## Exposure and limits

The forwarder is meant for loopback or a trusted LAN. It has no client ACL or rate limiting: firewall a LAN listener to trusted hosts, and never expose it as a public resolver. Built-in limits keep a misbehaving client from exhausting resources:

- At most 256 concurrent TCP clients; more wait in the kernel backlog.
- At most 1,024 pending upstream lookups; further cache misses get `SERVFAIL` immediately.
- Transient accept failures, such as running out of file descriptors, are retried rather than fatal.

On Windows, bind an explicit address: wildcard listeners are rejected because replies could leave from the wrong source address.

## Monitoring and diagnostics

With `-metrics 9100`, an unauthenticated HTTP server on `127.0.0.1:9100` provides:

| Endpoint | Purpose |
| --- | --- |
| `/metrics` | Prometheus text exposition. |
| `/debug/server/` | JSON with uptime, cache statistics, and query counters. |

To scrape it from Prometheus on the same host, or in the same network namespace for containers:

```yaml
scrape_configs:
  - job_name: dns-over-tls-forwarder
    static_configs:
      - targets: ['localhost:9100']
```

| Metric | What it reports |
| --- | --- |
| `dns_queries_total{protocol}` | Queries received over UDP or TCP. |
| `dns_responses_total{rcode}` | Responses by DNS status. |
| `dns_cache_hits_total`, `dns_cache_misses_total` | Fresh cache hits, and lookups with no cached response. |
| `dns_cache_stale_hits_total` | Stale answers served. |
| `dns_cache_refreshes_total` | Background refreshes queued. |
| `dns_cache_refreshes_completed_total` | Refresh attempts finished, successful or not. |
| `dns_cache_refreshes_dropped_total` | Refreshes skipped because one was pending or the queue was full. |
| `dns_singleflight_deduplications_total` | Queries that shared another query's lookup. |
| `dns_lookups_rejected_total` | Cache misses failed immediately because too many lookups were pending. |
| `dns_cache_entries`, `dns_cache_capacity` | Current entries and maximum capacity. |
| `dns_upstream_requests_total{upstream}`, `dns_upstream_errors_total{upstream}` | Exchange attempts, and transport or invalid-response failures. DNS errors such as `SERVFAIL` are not failures. |
| `dns_upstream_duration_seconds_total{upstream}` | Time spent in upstream exchanges, including waiting for a connection. |

## Cache behavior

TTLs are preserved by default and aged in every section; a cached response expires with its shortest TTL. Zero-TTL and truncated responses are not cached. Negative caching requires an SOA and lasts the minimum of its TTL, its MINIMUM field, other record TTLs, and 300 seconds.

After expiry, a positive answer may be returned with a 30-second TTL while one refresh is queued, for up to `-maxStale`. Negative answers, authenticated data, and DNSSEC-related queries or responses are never served stale. A refresh that returns an uncacheable success removes the old entry; a transient failure keeps it within the stale limit.

For strict freshness, leave `-minTTL` at zero and disable stale serving:

```sh
./dns-over-tls-forwarder -a 127.0.0.1:5353 -maxStale 0
```

The cache lives in memory, is cleared on restart, and has no flush endpoint.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Cannot bind port 53 | Another resolver may own the address, or the process lacks bind privileges. Try `127.0.0.1:5353`, or use the systemd unit. |
| No answers or `SERVFAIL` | Check outbound TCP 853, the upstream hostname and IP pair, system CA certificates, and the clock. Under load, check `dns_lookups_rejected_total`. |
| Blocking varies between queries | Use upstreams with matching filtering policies; the first response wins. |
| Metrics are unavailable | Set `-metrics`, query `localhost` on the same host, and check for a port conflict. |
| An old answer persists | Expired entries are served while they refresh; use `-maxStale 0`, and check whether `-minTTL` extends TTLs. |

## Development

```sh
go build ./...
go vet ./...
go test -race ./...
go test -run '^$' -bench . -benchmem ./proxy/...
go test ./proxy/internal/specialized -run '^$' -fuzz '^FuzzCache$' -fuzztime=30s
go test ./proxy -run '^$' -fuzz '^FuzzDNSMessageTransforms$' -fuzztime=30s
```

Tests use local fake upstreams and need no network access. CI tests on Linux, macOS, and Windows with the latest and minimum Go versions, and runs lint, fuzz smoke tests, govulncheck, and CodeQL. Actions are pinned to commits and updated by Dependabot along with Go modules.

Start with `main.go` for flags and process setup, `proxy/server.go` for forwarding and refreshes, `proxy/connpool.go` for connection reuse, and `proxy/cache.go` with `proxy/internal/specialized/` for caching.

## Credits and license

Thanks to [@empijei](https://github.com/empijei) for mentoring in design and style and contributing to early versions of the project.

Released under the [MIT License](LICENSE).
