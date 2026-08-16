# dns-over-tls-forwarder

[![CI](https://github.com/mikispag/dns-over-tls-forwarder/actions/workflows/ci.yml/badge.svg)](https://github.com/mikispag/dns-over-tls-forwarder/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mikispag/dns-over-tls-forwarder.svg)](https://pkg.go.dev/github.com/mikispag/dns-over-tls-forwarder)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mikispag/dns-over-tls-forwarder)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A high-performance, privacy-focused DNS-over-TLS (DoT) forwarding server with adaptive hybrid LRU/MFA caching, request deduplication, and Prometheus observability written in Go.

`dns-over-tls-forwarder` accepts standard DNS queries (UDP/TCP on port 53) from local applications, forwards them securely over TLS 1.3 to upstream DoT resolvers in parallel, and returns the fastest verified response while caching answers locally.

---

## Features

- **Encrypted DNS-over-TLS (RFC 7858)**: Enforces TLS 1.3 with SNI authentication to protect against DNS eavesdropping and spoofing.
- **Hybrid LRU / MFA Caching**: Dual-store priority queue that retains both recently accessed (LRU) and frequently accessed (MFA) records.
- **Negative Caching (RFC 2308)**: Caches `NXDOMAIN` and `NODATA` responses using upstream `SOA` TTLs to eliminate repeated lookups for nonexistent domains.
- **Singleflight Request Deduplication**: Coalesces concurrent in-flight queries for identical domains to mitigate cache stampedes.
- **Privacy-Enhancing**:
  - **EDNS0 Padding (RFC 7830 / RFC 8467)**: Pads outbound queries to 128-byte block boundaries to thwart packet-length fingerprinting.
  - **EDNS Client Subnet (ECS) Scrubbing (RFC 7871)**: Strips client subnet identifiers before forwarding to protect user privacy.
- **DNSSEC-Aware**: Partitions cache keys by DNSSEC OK (`DO`) bit to preserve signature validation integrity for downstream validators (`systemd-resolved`, `unbound`).
- **Resilient Connection Pool**: Persistent upstream TLS connections with health-probing to discard stale/closed sockets automatically.
- **Production Observability**: Built-in Prometheus metrics exporter (`/metrics`), pprof profiling, and JSON stats handler.
- **Zero Configuration Defaults**: Works out of the box with Cloudflare and Google DoT upstreams.

---

## Installation

### Using `go install`

```bash
go install github.com/mikispag/dns-over-tls-forwarder@latest
```

### Build from source

```bash
git clone https://github.com/mikispag/dns-over-tls-forwarder.git
cd dns-over-tls-forwarder
go build -o dns-over-tls-forwarder .
```

---

## Quick Start

### Basic Usage

Listen locally on loopback interface (`127.0.0.1:53`) using default upstreams:

```bash
sudo ./dns-over-tls-forwarder -a "127.0.0.1:53"
```

### With Custom Upstreams & Prometheus Metrics

```bash
sudo ./dns-over-tls-forwarder \
  -a "127.0.0.1:53" \
  -s "one.one.one.one:853@1.1.1.1,dns.quad9.net:853@9.9.9.9" \
  -minTTL 300 \
  -pprof 9100 \
  -d
```

---

## Command-Line Options

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-a` | string | `:53` | Address and port to listen on. Use `127.0.0.1:53` for loopback only. |
| `-s` | string | `one.one.one.one:853@1.1.1.1,dns.google:853@8.8.8.8` | Comma-separated list of upstream DoT servers (`hostname:port@ip`). |
| `-minTTL` | int | `60` | Minimum TTL (in seconds) returned to clients (clamped between 60 and $2^{31}-1$). |
| `-pprof` | int | `0` | Port for pprof profiling and `/metrics` endpoint. Disabled if set to `0`. |
| `-em` | bool | `false` | Collect eviction statistics in cache metrics (doubles cache memory tracking). |
| `-d` | bool | `false` | Enable verbose debug logging. |
| `-l` | string | `""` | Path to log file (logs to stdout as well if set). |

---

## Popular Upstream DNS-over-TLS Servers

| Provider | Description | Flag Value |
| :--- | :--- | :--- |
| **Cloudflare** | Standard / Fast | `one.one.one.one:853@1.1.1.1` |
| **Cloudflare Security** | Malware blocking | `security.cloudflare-dns.com:853@1.1.1.2` |
| **Google** | Standard | `dns.google:853@8.8.8.8` |
| **Quad9** | Malware blocking (recommended) | `dns.quad9.net:853@9.9.9.9` |
| **Quad9 (Unfiltered)** | No blocking | `dns10.quad9.net:853@9.9.9.10` |
| **Mullvad** | Ad-blocking / Privacy | `adblock.doh.mullvad.net:853@194.242.2.3` |

Upstream format is `hostname:port@ip`, where `hostname` is used for TLS SNI validation and certificate verification, and `ip` is the target IP address to connect to.

---

## Observability & Metrics

When `-pprof <port>` is enabled, the forwarder exposes:

- **`/metrics`**: Prometheus text format metrics:
  - `dns_queries_total{protocol="udp|tcp"}`: Total query counter.
  - `dns_responses_total{rcode="..."}`: Response counter by RCODE (`NOERROR`, `NXDOMAIN`, `SERVFAIL`, `FORMERR`).
  - `dns_cache_hits_total`, `dns_cache_misses_total`, `dns_cache_refreshes_total`.
  - `dns_cache_entries`, `dns_cache_capacity`.
  - `dns_singleflight_deduplications_total`.
  - `dns_upstream_requests_total{upstream="..."}`, `dns_upstream_errors_total{upstream="..."}`, `dns_upstream_duration_seconds_total{upstream="..."}`.
- **`/debug/server/`**: Detailed JSON cache performance and server statistics.
- **`/debug/pprof/`**: Go standard runtime profiling endpoints.

---

## Systemd Service

A ready-to-use systemd service unit is available in [`debian/dns-over-tls-forwarder.service`](debian/dns-over-tls-forwarder.service):

```ini
[Unit]
Description=DNS-over-TLS forwarder
After=network.target

[Service]
DynamicUser=yes
LimitNOFILE=32768
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/usr/local/bin/dns-over-tls-forwarder -a 127.0.0.1:53
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

To install:
```bash
sudo cp dns-over-tls-forwarder /usr/local/bin/
sudo cp debian/dns-over-tls-forwarder.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dns-over-tls-forwarder
```

---

## Credits

Special thanks to [@empijei](https://github.com/empijei) for mentoring in design and style and contributing to early versions of this project.

## License

MIT License. See [LICENSE](LICENSE) for details.
