# dns-over-tls-forwarder

[![CI](https://github.com/mikispag/dns-over-tls-forwarder/actions/workflows/ci.yml/badge.svg)](https://github.com/mikispag/dns-over-tls-forwarder/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mikispag/dns-over-tls-forwarder.svg)](https://pkg.go.dev/github.com/mikispag/dns-over-tls-forwarder)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mikispag/dns-over-tls-forwarder)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Give ordinary DNS clients an encrypted path to upstream resolvers.**

`dns-over-tls-forwarder` is a Go service that accepts DNS over UDP and TCP, caches responses locally, and forwards cache misses over authenticated TLS 1.3. Run it on your workstation or a trusted network gateway without requiring applications to speak DNS-over-TLS.

```text
Applications ── ordinary DNS over UDP/TCP ──► dns-over-tls-forwarder
                                               ├── local cache
                                               └── DNS over TLS ──► upstream resolvers
```

It combines persistent upstream connections, concurrent resolver queries, request deduplication, and a cache that retains both recently and frequently accessed answers. Prometheus metrics expose query volume, cache behavior, and upstream failures.

## Try it locally

Requires **Go 1.27 or newer**, system CA certificates, and outbound TCP access to your upstreams (normally port 853). Start on an unprivileged loopback port:

```sh
git clone https://github.com/mikispag/dns-over-tls-forwarder.git
cd dns-over-tls-forwarder
go build -o dns-over-tls-forwarder .
./dns-over-tls-forwarder -a 127.0.0.1:5353 -metrics 9100
```

In another terminal, query it with `dig` and inspect its metrics:

```sh
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com A +tcp
curl http://localhost:9100/metrics
```

Both DNS queries should return an answer. Repeating a query should increase `dns_cache_hits_total`. Stop the process with Ctrl+C.

This verifies the forwarder without changing your system resolver. To use it for normal application lookups, bind to port 53 and configure your operating system or router to use its address. See [running with systemd](#running-with-systemd).

Alternatively, install the binary with Go:

```sh
go install github.com/mikispag/dns-over-tls-forwarder@latest
```

Go places it in `GOBIN`, or normally `$(go env GOPATH)/bin`; add that directory to `PATH` if necessary.

## How forwarding works

- **Encrypted upstream transport.** Connections require TLS 1.3 or newer and authenticate the resolver certificate against its hostname using the system trust store.
- **Concurrent upstream queries.** Cache misses race the configured upstreams. The first matching `NOERROR` or `NXDOMAIN` response wins; other DNS errors are used only if no such response arrives. This is a race, not a primary/backup list or a consensus check.
- **Connection reuse and deduplication.** Each upstream has a pool limited to two connections, including active and idle sockets. Concurrent equivalent requests share one upstream lookup. A lookup, including connection setup and retries, has a 10-second deadline; a waiting client can cancel independently.
- **Local caching.** The default capacity is 65,536 entries, split between least recently used (LRU) and most frequently accessed (MFA) stores. The cache handles positive answers and SOA-bearing negative responses. Eligible expired positive answers can be served briefly while a background refresh runs.
- **DNS and EDNS handling.** Outbound queries remove EDNS Client Subnet (ECS) options and pad messages to 128-byte boundaries. Cache keys separate `DO`, `CD`, `RD`, and `AD` policies; requests with other EDNS options bypass caching and deduplication. UDP replies respect the client’s size limit and signal truncation so it can retry over TCP. The forwarder does not perform DNSSEC validation itself.

The client-to-forwarder connection is ordinary, unencrypted DNS. Each configured upstream can see queries sent to it. TLS protects that hop from network observers; it does not hide queries from the resolver. See [cache behavior](#cache-behavior) for freshness and DNSSEC policy.

## Choosing upstreams

Use a comma-separated list with no spaces:

```text
TLS-hostname:port@IP-address
```

The hostname is used for TLS SNI and certificate verification; the address after `@` is used for the connection. Supplying an IP avoids depending on another DNS resolver to bootstrap the TLS hostname.

| Resolver | Value for `-s` | Provider documentation |
| --- | --- | --- |
| Cloudflare | `one.one.one.one:853@1.1.1.1` | [DNS over TLS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-tls/) |
| Google Public DNS | `dns.google:853@8.8.8.8` | [DNS over TLS](https://developers.google.com/speed/public-dns/docs/dns-over-tls) |
| Quad9 with threat blocking | `dns.quad9.net:853@9.9.9.9` | [Service addresses](https://docs.quad9.net/services/) |

Cloudflare and Google are the defaults. To use only Quad9:

```sh
./dns-over-tls-forwarder -a 127.0.0.1:5353 -s dns.quad9.net:853@9.9.9.9
```

Choose upstreams with compatible filtering policies. Mixing a blocking resolver with an unfiltered one makes the result depend on which responds first. Hostname-only addresses such as `dns.google:853` also work, but require working system DNS. IPv6 overrides are accepted with or without brackets, for example `dns.google:853@[2001:4860:4860::8888]`. Invalid upstream addresses fail startup with an explanation.

## Command line reference

Run `dns-over-tls-forwarder -h` for the built-in help.

| Flag | Default | Behavior |
| --- | --- | --- |
| `-a` | `127.0.0.1:53` | Listen address for both UDP and TCP. Set an explicit LAN address to serve network clients. |
| `-s` | `one.one.one.one:853@1.1.1.1,dns.google:853@8.8.8.8` | Upstreams to query concurrently, separated by commas. |
| `-minTTL` | `0` | Preserve upstream answer TTLs by default. A positive value deliberately extends shorter answer TTLs, including zero TTLs. Valid range: 0–2,147,483,647 seconds. |
| `-maxStale` | `1h` | Maximum age after expiry for eligible stale positive answers. Use `0` to disable stale serving. Accepts Go durations such as `30m`. |
| `-metrics` | `0` | Enable metrics and JSON diagnostics on `127.0.0.1:<port>`. Zero disables HTTP. |
| `-em` | `false` | Track recently evicted cache entries for additional diagnostics, with extra memory overhead. |
| `-d` | `false` | Enable debug logging, including query names. Operational messages remain enabled without it. |
| `-l` | empty | Append logs to a file as well as stdout. An unwritable file causes startup to fail. |

The CLI uses a fixed cache capacity. The Go constructor accepts a cache size for embedded use; a negative size disables caching. Use `-maxStale 0` when answers must not outlive their cached TTLs.

## Running with systemd

The supplied [service unit](debian/dns-over-tls-forwarder.service) uses a dynamic user and grants `CAP_NET_BIND_SERVICE` to bind port 53 without running the service as root. It binds to loopback by default.

To install the service with metrics enabled, copy the binary and unit and add a drop-in:

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

Check the service and query it before changing your system DNS settings:

```sh
systemctl status dns-over-tls-forwarder
dig @127.0.0.1 example.com A
curl http://localhost:9100/metrics
```

For LAN use, bind to the intended LAN address and restrict access with your firewall. The forwarder has no client ACL or rate limiter. It should not be exposed as a public recursive DNS service. Windows requires an explicit local address: wildcard binds are rejected because the DNS transport cannot preserve the reply source address there.

## Monitoring and diagnostics

With `-metrics 9100`, the HTTP server binds to `127.0.0.1:9100` and provides:

| Endpoint | Purpose |
| --- | --- |
| `/metrics` | Prometheus text exposition. |
| `/debug/server/` | JSON with uptime, cache statistics, query counters, and deduplication counts. |

Example Prometheus configuration when Prometheus runs on the same host:

```yaml
scrape_configs:
  - job_name: dns-over-tls-forwarder
    static_configs:
      - targets: ['localhost:9100']
```

A container has its own loopback interface, so this target assumes the same network namespace as the forwarder.

Useful metrics include:

| Metric | What it reports |
| --- | --- |
| `dns_queries_total{protocol}` | Requests handled over UDP or TCP. |
| `dns_responses_total{rcode}` | Response counts by DNS status. |
| `dns_cache_hits_total`, `dns_cache_misses_total` | Fresh cache hits and lookups with no cached response. |
| `dns_cache_stale_hits_total` | Stale answers served. |
| `dns_cache_refreshes_total` | Background refreshes successfully queued. |
| `dns_cache_refreshes_completed_total` | Completed background refresh attempts, successful or failed. |
| `dns_cache_refreshes_dropped_total` | Refresh requests skipped because one is already pending or the queue is full. |
| `dns_singleflight_deduplications_total` | Waiting followers that received a shared result without starting another lookup. |
| `dns_cache_entries`, `dns_cache_capacity` | Current entries and maximum capacity. |
| `dns_upstream_requests_total{upstream}`, `dns_upstream_errors_total{upstream}` | Exchange attempts and transport or invalid-response failures. Canceled losing lookups and DNS status codes such as `SERVFAIL` do not count as failures. |
| `dns_upstream_duration_seconds_total{upstream}` | Cumulative time spent in upstream exchanges, including connection acquisition. |

The HTTP endpoints have no authentication; keep access restricted if you proxy them elsewhere.

## Cache behavior

By default, the forwarder preserves upstream TTLs and ages records in the Answer, Authority, and Additional sections. A cached response expires when its shortest applicable record TTL expires. Zero-TTL responses and truncated responses are not cached. Negative caching requires an SOA and uses the minimum of its TTL, SOA MINIMUM, other record TTLs, and a 300-second cap.

Expired positive answers may be returned with a 30-second TTL while a refresh is queued, for at most `-maxStale` after expiry (one hour by default). Negative answers, authenticated responses, and DNSSEC-sensitive requests or responses are never served stale. Duplicate refresh requests are coalesced. A successful uncacheable refresh invalidates the old entry; transient upstream failures leave eligible stale data available within the configured limit.

For strict freshness, leave `-minTTL` at zero and disable stale serving:

```sh
./dns-over-tls-forwarder -a 127.0.0.1:5353 -maxStale 0
```

The cache lives in memory and is cleared when the process restarts. It has no cache-flush endpoint. For LAN use, restrict access with a firewall: the service has no client ACL or per-client rate limiter.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Cannot bind port 53 | Another resolver may already own the address, or the process may lack bind privileges. Start with `127.0.0.1:5353`, or use the systemd unit. |
| No answers or `SERVFAIL` | Check outbound TCP 853, the upstream hostname/IP pair, system CA certificates, and the system clock. Lookups time out after 10 seconds, including connection setup and retries. |
| Blocking varies between queries | Use upstreams with matching filtering policies; the first successful or negative response wins. |
| Metrics are unavailable | Set `-metrics`, use `localhost` on the same host, and check for a port conflict. |
| An old answer persists | Expired cache entries are served while refreshes are attempted. Use `-maxStale 0` to disable this behavior, and check whether `-minTTL` is intentionally extending TTLs. |

## Development

```sh
go build ./...
go vet ./...
go test ./...
go test -race -coverprofile=coverage.out ./...
go test -run '^$' -bench . -benchmem ./proxy/...
go test ./proxy/internal/specialized -run '^$' -fuzz '^FuzzCache$' -fuzztime=30s -parallel=2
go test ./proxy -run '^$' -fuzz '^FuzzDNSMessageTransforms$' -fuzztime=30s -parallel=2
```

The tests use local fake upstreams and do not require public DNS access. CI builds and tests on Linux, macOS, and Windows, checks the minimum Go version, and runs native fuzz smoke tests, lint, vulnerability scanning, and CodeQL. Workflow actions are pinned to commits and monitored by Dependabot alongside Go modules. Benchmarks measure the local test workloads; they are not public-resolver latency claims.

Start with `main.go` for flags and process setup, `proxy/server.go` for forwarding and refreshes, `proxy/connpool.go` for connection reuse, and `proxy/cache.go` plus `proxy/internal/specialized/` for caching.

## Credits and license

Thanks to [@empijei](https://github.com/empijei) for mentoring in design and style and contributing to early versions of the project.

Released under the [MIT License](LICENSE).
