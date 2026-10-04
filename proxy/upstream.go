package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type upstreamConfig struct {
	address    string
	serverName string
}

// ValidateUpstreams checks TLS server names, ports, and optional IP overrides.
// An upstream is hostname:port or hostname:port@IP. IPv6 overrides may be
// written with or without brackets.
func ValidateUpstreams(upstreamServers ...string) error {
	if len(upstreamServers) == 0 {
		return errors.New("at least one upstream server is required")
	}
	for _, addr := range upstreamServers {
		if _, err := parseUpstream(addr); err != nil {
			return fmt.Errorf("invalid upstream %q: %w", addr, err)
		}
	}
	return nil
}

func parseUpstream(addr string) (upstreamConfig, error) {
	endpoint, override, hasOverride := strings.Cut(strings.TrimSpace(addr), "@")
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return upstreamConfig{}, err
	}
	if net.ParseIP(host) == nil && !validHostname(host) {
		return upstreamConfig{}, errors.New("invalid TLS server name")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 || strings.Trim(port, "0123456789") != "" {
		return upstreamConfig{}, errors.New("port must be a number between 1 and 65535")
	}
	address := net.JoinHostPort(host, port)
	if hasOverride {
		if strings.HasPrefix(override, "[") && strings.HasSuffix(override, "]") {
			override = override[1 : len(override)-1]
		}
		ip := net.ParseIP(override)
		if ip == nil {
			return upstreamConfig{}, errors.New("address after @ must be an IP literal")
		}
		address = net.JoinHostPort(ip.String(), port)
	}
	return upstreamConfig{address: address, serverName: host}, nil
}

func validHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}
