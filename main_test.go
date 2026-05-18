package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseBlocklistDomain(t *testing.T) {
	tests := map[string]string{
		"doubleclick.net":                         "doubleclick.net",
		".googlesyndication.com":                  "googlesyndication.com",
		"*.adservice.google.com":                  "adservice.google.com",
		"0.0.0.0 pagead2.googlesyndication.com":   "pagead2.googlesyndication.com",
		"127.0.0.1 googleads.g.doubleclick.net #": "googleads.g.doubleclick.net",
		"||imasdk.googleapis.com^$third-party":    "imasdk.googleapis.com",
	}

	for line, want := range tests {
		got, ok := parseBlocklistDomain(line)
		if !ok {
			t.Fatalf("expected %q to parse", line)
		}
		if got != want {
			t.Fatalf("parseBlocklistDomain(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestParseBlocklistDomainIgnoresUnsupportedRules(t *testing.T) {
	for _, line := range []string{
		"",
		"# comment",
		"! adblock comment",
		"@@||allowed.example^",
		"/pagead/",
		"0.0.0.0",
	} {
		if got, ok := parseBlocklistDomain(line); ok {
			t.Fatalf("expected %q to be ignored, got %q", line, got)
		}
	}
}

func TestBlocklistBlocksSubdomainsForPlainDomainEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(path, []byte("doubleclick.net\n"), 0600); err != nil {
		t.Fatal(err)
	}

	bl, err := loadBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, domain := range []string{"doubleclick.net", "ad.doubleclick.net", "stats.g.doubleclick.net"} {
		if !bl.isBlocked(domain) {
			t.Fatalf("expected %q to be blocked", domain)
		}
	}
	if bl.isBlocked("notdoubleclick.net") {
		t.Fatal("expected unrelated domain to be allowed")
	}
}

func TestBuiltInAdDomainsAreBlocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}

	bl, err := loadBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}

	for _, domain := range []string{
		"googleads.g.doubleclick.net",
		"pagead2.googlesyndication.com",
		"subdomain.googlesyndication.com",
		"beacons.gcp.gvt2.com",
	} {
		if !bl.isBlocked(domain) {
			t.Fatalf("expected built-in domain %q to be blocked", domain)
		}
	}
}
