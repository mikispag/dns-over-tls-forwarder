package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "dns-forwarder-cli-test-")
	if err != nil {
		panic(err)
	}
	testBinary = filepath.Join(dir, "forwarder.exe")
	cmd := exec.Command("go", "build", "-o", testBinary, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		_, _ = os.Stderr.Write(output)
		_ = os.RemoveAll(dir)
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func cliCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return exec.CommandContext(ctx, testBinary, args...)
}

func TestCLIHelp(t *testing.T) {
	output, err := cliCommand(t, "-h").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	var flags []string
	for _, match := range regexp.MustCompile(`(?m)^  -(\w+)`).FindAllStringSubmatch(string(output), -1) {
		flags = append(flags, match[1])
	}
	want := []string{"a", "d", "em", "l", "maxStale", "metrics", "minTTL", "s"}
	if !slices.Equal(flags, want) {
		t.Fatalf("flags = %v; want %v", flags, want)
	}
}

func TestCLIInvalidConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"-s", ""}, {"-s", "dns.test:853@not-an-ip"},
		{"-s", "dns.test:0"}, {"-s", "dns.test:853,"},
		{"-metrics", "-1"}, {"-metrics", "65536"},
		{"-minTTL", "-1"}, {"-maxStale", "-1s"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := cliCommand(t, append([]string{"-a", "127.0.0.1:0"}, args...)...)
			output, err := cmd.CombinedOutput()
			if err == nil || len(output) == 0 {
				t.Fatalf("invalid configuration must fail with an explanation: err=%v output=%q", err, output)
			}
		})
	}
}

func TestCLIMetricsBindFailure(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	output, err := cliCommand(t, "-a", "127.0.0.1:0", "-metrics", port).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "metrics") {
		t.Fatalf("HTTP bind failure must stop startup visibly: err=%v output=%q", err, output)
	}
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func TestCLILoggingAndDiagnostics(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(strconv.FormatBool(debug), func(t *testing.T) {
			dir := t.TempDir()
			stdout, err := os.Create(filepath.Join(dir, "stdout"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stdout.Close() }()
			logPath := filepath.Join(dir, "forwarder.log")
			dnsPort, metricsPort, upstreamPort := freeTCPPort(t), freeTCPPort(t), freeTCPPort(t)
			args := []string{"-a", "127.0.0.1:" + dnsPort, "-metrics", metricsPort,
				"-l", logPath, "-s", "dns.test:" + upstreamPort + "@127.0.0.1"}
			if debug {
				args = append(args, "-d")
			}
			cmd := exec.Command(testBinary, args...)
			cmd.Stdout, cmd.Stderr = stdout, stdout
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			client := &http.Client{Timeout: 200 * time.Millisecond}
			base := "http://127.0.0.1:" + metricsPort
			deadline := time.Now().Add(5 * time.Second)
			for {
				resp, err := client.Get(base + "/metrics")
				if err == nil {
					_ = resp.Body.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("diagnostics did not start:", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			for path, status := range map[string]int{"/metrics": http.StatusOK, "/debug/server/": http.StatusOK, "/debug/": http.StatusNotFound, "/": http.StatusNotFound} {
				resp, err := client.Get(base + path)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != status {
					t.Fatalf("%s returned %s", path, resp.Status)
				}
			}
			for {
				conn, err := net.DialTimeout("tcp", "127.0.0.1:"+dnsPort, 200*time.Millisecond)
				if err == nil {
					_ = conn.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("DNS listener did not start:", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			conn, err := net.DialTimeout("udp", "127.0.0.1:"+dnsPort, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			q := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'p', 'r', 'i', 'v', 'a', 't', 'e', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
			if _, err := conn.Write(q); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, 512)
			n, err := conn.Read(response)
			if err != nil || n < 12 || binary.BigEndian.Uint16(response[2:4])&15 != 2 {
				t.Fatalf("expected SERVFAIL from unavailable upstream: n=%d err=%v", n, err)
			}
			for _, path := range []string{stdout.Name(), logPath} {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if len(data) == 0 {
					t.Fatalf("no operational logs in %s", path)
				}
				if strings.Contains(string(data), "private.example") != debug {
					t.Fatalf("query privacy does not match debug=%v in %s: %s", debug, path, data)
				}
			}
		})
	}
}
