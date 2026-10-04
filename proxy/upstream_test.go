package proxy

import "testing"

func TestParseUpstream(t *testing.T) {
	for _, tt := range []struct {
		input, address, serverName string
	}{
		{"dns.google:853", "dns.google:853", "dns.google"},
		{"dns.google:853@8.8.8.8", "8.8.8.8:853", "dns.google"},
		{"dns.google:853@2001:4860:4860::8888", "[2001:4860:4860::8888]:853", "dns.google"},
		{"dns.google:853@[2001:4860:4860::8888]", "[2001:4860:4860::8888]:853", "dns.google"},
		{"[::1]:8853", "[::1]:8853", "::1"},
		{"127.0.0.1:8853", "127.0.0.1:8853", "127.0.0.1"},
		{" localhost:8853 ", "localhost:8853", "localhost"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseUpstream(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if got.address != tt.address || got.serverName != tt.serverName {
				t.Fatalf("parsed = %+v, want address=%s serverName=%s", got, tt.address, tt.serverName)
			}
		})
	}
}

func TestValidateUpstreamsRejectsInvalidConfiguration(t *testing.T) {
	if err := ValidateUpstreams(); err == nil {
		t.Error("accepted empty upstream list")
	}
	for _, input := range []string{
		"", " ", "dns.google", ":853", "dns.google:", "dns.google:https",
		"dns.google:0", "dns.google:65536", "dns.google:-1", "dns.google:+853",
		"dns.google:853@", "dns.google:853@invalid", "dns.google:853@8.8.8.8@8.8.4.4",
		"dns.google:853@[::1", "dns.google:853@8.8.8.8:853", "bad host:853@8.8.8.8",
		"-invalid.example:853", "invalid-.example:853", "bad..example:853",
	} {
		t.Run(input, func(t *testing.T) {
			if err := ValidateUpstreams("dns.google:853@8.8.8.8", input); err == nil {
				t.Error("accepted invalid upstream")
			}
		})
	}
}
