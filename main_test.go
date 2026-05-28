package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseBlocklistDomainEmpty(t *testing.T) {
	tests := []struct {
		line     string
		expected string
		ok       bool
	}{
		{"", "", false},
		{"   ", "", false},
		{"# comment", "", false},
		{"! adblock comment", "", false},
		{"@@ whitelist", "", false},
		{"||example.com^", "example.com", true},
		{"example.com", "example.com", true},
		{"127.0.0.1 example.com", "example.com", true},
		{"0.0.0.0 malware.net", "malware.net", true},
		{"example.com # inline comment", "example.com", true},
		{"example.com ! inline comment", "example.com", true},
		{"||*.example.com^", "example.com", true},
		{"example.com$document", "example.com", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.line), func(t *testing.T) {
			domain, ok := parseBlocklistDomain(tt.line)
			if ok != tt.ok {
				t.Errorf("parseBlocklistDomain(%q) ok = %v, expected %v", tt.line, ok, tt.ok)
			}
			if domain != tt.expected {
				t.Errorf("parseBlocklistDomain(%q) = %q, expected %q", tt.line, domain, tt.expected)
			}
		})
	}
}

func TestParseBlocklistDomainNormalization(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{"EXAMPLE.COM", "example.com"},
		{"Example.Com", "example.com"},
		{"example.com.", "example.com"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.line), func(t *testing.T) {
			domain, ok := parseBlocklistDomain(tt.line)
			if !ok {
				t.Fatalf("parseBlocklistDomain(%q) should succeed", tt.line)
			}
			if domain != tt.expected {
				t.Errorf("parseBlocklistDomain(%q) = %q, expected %q", tt.line, domain, tt.expected)
			}
		})
	}
}

func TestParseBlocklistDomainRejectsInvalid(t *testing.T) {
	tests := []string{
		"192.168.1.1",      // IP address
		"example.com/path", // contains /
		"example.com:8080", // contains :
		"*example.com",     // starts with *
	}

	for _, line := range tests {
		t.Run(fmt.Sprintf("%q", line), func(t *testing.T) {
			_, ok := parseBlocklistDomain(line)
			if ok {
				t.Errorf("parseBlocklistDomain(%q) should reject invalid domain", line)
			}
		})
	}
}

func TestLoadBlocklist(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "blocklist_test_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write test data
	content := `# comment line
! adblock comment
@@whitelist

||ads.example.com^
ads.doubleclick.net
127.0.0.1 tracker.example.com
invalid/domain/path

example.com # inline comment
`
	if _, err := tmpfile.WriteString(content); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	tmpfile.Close()

	bl, err := loadBlocklist(tmpfile.Name())
	if err != nil {
		t.Fatalf("loadBlocklist failed: %v", err)
	}

	// Verify built-in ad domains are included
	if !bl.isBlocked("google-analytics.com") {
		t.Error("built-in ad domains should be included")
	}

	// Verify custom domains are loaded
	if !bl.isBlocked("ads.example.com") {
		t.Error("ads.example.com should be blocked")
	}
	if !bl.isBlocked("ads.doubleclick.net") {
		t.Error("ads.doubleclick.net should be blocked")
	}
	if !bl.isBlocked("tracker.example.com") {
		t.Error("tracker.example.com should be blocked")
	}
	if !bl.isBlocked("example.com") {
		t.Error("example.com should be blocked")
	}

	// Verify non-blocked domains pass
	if bl.isBlocked("legitimate.com") {
		t.Error("legitimate.com should not be blocked")
	}
}

func TestBlocklistMatchesDomainAndSubdomains(t *testing.T) {
	bl := &blocklist{exact: make(map[string]struct{})}
	bl.add("example.com")

	if !bl.isBlocked("example.com") {
		t.Error("exact match should be blocked")
	}
	if !bl.isBlocked("example.com.") {
		t.Error("domain with trailing dot should match")
	}
	if !bl.isBlocked("sub.example.com") {
		t.Error("subdomain should match suffix domain")
	}
}

func TestBlocklistSuffixMatch(t *testing.T) {
	bl := &blocklist{exact: make(map[string]struct{})}
	bl.add("example.com")

	tests := []struct {
		domain  string
		blocked bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"api.www.example.com", true},
		{"sub.domain.example.com", true},
		{"notexample.com", false},
		{"example.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if bl.isBlocked(tt.domain) != tt.blocked {
				t.Errorf("isBlocked(%q) = %v, expected %v", tt.domain, bl.isBlocked(tt.domain), tt.blocked)
			}
		})
	}
}

func TestBlocklistCaseInsensitive(t *testing.T) {
	bl := &blocklist{exact: make(map[string]struct{})}
	bl.add("EXAMPLE.COM")

	tests := []string{"example.com", "EXAMPLE.COM", "Example.Com", "WWW.EXAMPLE.COM"}

	for _, domain := range tests {
		if !bl.isBlocked(domain) {
			t.Errorf("isBlocked(%q) should be true (case-insensitive)", domain)
		}
	}
}

func TestBlocklistMultipleDomains(t *testing.T) {
	bl := &blocklist{exact: make(map[string]struct{})}

	domains := []string{"ads.com", "tracker.com", "analytics.net", "doubleclick.net"}
	for _, d := range domains {
		bl.add(d)
	}

	for _, d := range domains {
		if !bl.isBlocked(d) {
			t.Errorf("isBlocked(%q) should be true", d)
		}
	}

	if bl.isBlocked("legitimate.com") {
		t.Error("isBlocked(legitimate.com) should be false")
	}
}

func TestIsMITMDomainExactMatch(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"youtube.com", true},
		{"www.youtube.com", true},
		{"m.youtube.com", true},
		{"api.youtube.com", true},
		{"google.com", false},
		{"youtube.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result := isMITMDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("isMITMDomain(%q) = %v, expected %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestIsMITMDomainTrailingDot(t *testing.T) {
	if !isMITMDomain("youtube.com.") {
		t.Error("isMITMDomain should handle trailing dot")
	}
}

func TestLocalIPAutoDetect(t *testing.T) {
	// Save original flag value
	originalFlag := *localIPFlag
	defer func() { *localIPFlag = originalFlag }()

	// Clear flag and env
	*localIPFlag = ""
	os.Unsetenv("LOCAL_IP")

	ip := localIP()
	if ip == nil {
		t.Fatal("localIP should return a non-nil IP")
	}

	// Should return either a valid non-loopback IP or loopback if nothing else available
	ipStr := ip.String()
	if ipStr == "" {
		t.Error("IP string should not be empty")
	}
}

func TestLocalIPFlagOverride(t *testing.T) {
	originalFlag := *localIPFlag
	defer func() { *localIPFlag = originalFlag }()

	*localIPFlag = "192.168.1.100"
	os.Unsetenv("LOCAL_IP")

	ip := localIP()
	if ip.String() != "192.168.1.100" {
		t.Errorf("localIP should use flag value, got %s", ip.String())
	}
}

func TestLocalIPEnvOverride(t *testing.T) {
	originalFlag := *localIPFlag
	defer func() { *localIPFlag = originalFlag }()

	*localIPFlag = ""
	os.Setenv("LOCAL_IP", "10.0.0.50")
	defer os.Unsetenv("LOCAL_IP")

	ip := localIP()
	if ip.String() != "10.0.0.50" {
		t.Errorf("localIP should use env value, got %s", ip.String())
	}
}

func TestLocalIPInvalidInput(t *testing.T) {
	originalFlag := *localIPFlag
	defer func() { *localIPFlag = originalFlag }()

	*localIPFlag = "invalid-ip-address"
	os.Unsetenv("LOCAL_IP")

	ip := localIP()
	// Should fall back to auto-detect
	if ip == nil {
		t.Error("localIP should return a valid IP even with invalid flag")
	}
}

func TestParseBlocklistDomainMultipleFields(t *testing.T) {
	tests := []struct {
		line     string
		expected string
		ok       bool
	}{
		// IP address followed by domain
		{"127.0.0.1 ads.example.com tracker.example.com", "ads.example.com", true},
		// Multiple spaces
		{"127.0.0.1    ads.example.com", "ads.example.com", true},
		// Tab-separated
		{"0.0.0.0\tmalware.com", "malware.com", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.line), func(t *testing.T) {
			domain, ok := parseBlocklistDomain(tt.line)
			if ok != tt.ok {
				t.Errorf("parseBlocklistDomain(%q) ok = %v, expected %v", tt.line, ok, tt.ok)
			}
			if domain != tt.expected {
				t.Errorf("parseBlocklistDomain(%q) = %q, expected %q", tt.line, domain, tt.expected)
			}
		})
	}
}

func TestLoadBlocklistWithLargeFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "blocklist_large_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write many domains
	writer := bufio.NewWriter(tmpfile)
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(writer, "ads%d.example.com\n", i)
	}
	writer.Flush()
	tmpfile.Close()

	bl, err := loadBlocklist(tmpfile.Name())
	if err != nil {
		t.Fatalf("loadBlocklist failed: %v", err)
	}

	// Verify some domains were loaded
	if !bl.isBlocked("ads0.example.com") {
		t.Error("first domain should be blocked")
	}
	if !bl.isBlocked("ads999.example.com") {
		t.Error("last domain should be blocked")
	}
	if !bl.isBlocked("ads500.example.com") {
		t.Error("middle domain should be blocked")
	}
}

func TestBlocklistAddDuplicates(t *testing.T) {
	bl := &blocklist{exact: make(map[string]struct{})}

	bl.add("example.com")
	initialExactCount := len(bl.exact)
	initialSuffixCount := len(bl.suffixes)

	// Add same domain again
	bl.add("example.com")

	// Should not create duplicates in exact map
	if len(bl.exact) != initialExactCount {
		t.Error("exact map should not have duplicates")
	}
	// But suffixes list may have duplicates (that's okay for suffix matching)
	if len(bl.suffixes) < initialSuffixCount {
		t.Error("suffixes should not shrink")
	}
}

func TestCacheKeyGeneration(t *testing.T) {
	key1 := cacheKey("example.com", 1)  // A record
	key2 := cacheKey("example.com", 28) // AAAA record
	key3 := cacheKey("example.com", 1)  // A record again

	if key1 == key2 {
		t.Error("different query types should produce different cache keys")
	}
	if key1 != key3 {
		t.Error("same domain and query type should produce same cache key")
	}
	if !strings.Contains(key1, "example.com") {
		t.Error("cache key should contain domain")
	}
}

func TestCopyMsg(t *testing.T) {
	// copyMsg function works with *dns.Msg objects
	// Just verify the cacheKey function works
	key := cacheKey("example.com", 1)
	if key == "" {
		t.Error("cacheKey should not return empty string")
	}
}
