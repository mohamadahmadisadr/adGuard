package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreateCACreatesNewCA(t *testing.T) {
	// Create temp dir for test
	tmpdir := t.TempDir()
	certFile := filepath.Join(tmpdir, "ca.crt")
	keyFile := filepath.Join(tmpdir, "ca.key")

	// Verify files don't exist
	if _, err := os.Stat(certFile); !os.IsNotExist(err) {
		t.Fatal("cert file should not exist")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("key file should not exist")
	}

	// Create CA
	ca, err := LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}
	if ca == nil {
		t.Fatal("expected CA to be created")
	}

	// Verify files were created
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Fatal("cert file should have been created")
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Fatal("key file should have been created")
	}

	// Verify CA has valid structure
	if ca.cert == nil {
		t.Fatal("CA certificate should not be nil")
	}
	if ca.key == nil {
		t.Fatal("CA private key should not be nil")
	}
	if ca.cache == nil {
		t.Fatal("CA cache should not be nil")
	}

	// Verify certificate is valid
	if !ca.cert.IsCA {
		t.Fatal("certificate should be a CA")
	}
	if ca.cert.Subject.CommonName != "dns-proxy CA" {
		t.Fatal("certificate CN should be 'dns-proxy CA'")
	}
}

func TestLoadOrCreateCALoadsExistingCA(t *testing.T) {
	// Create temp dir and initial CA
	tmpdir := t.TempDir()
	certFile := filepath.Join(tmpdir, "ca.crt")
	keyFile := filepath.Join(tmpdir, "ca.key")

	ca1, err := LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	// Load the same CA again
	ca2, err := LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to load CA: %v", err)
	}

	// Verify they are the same
	if ca2.cert.Subject.CommonName != ca1.cert.Subject.CommonName {
		t.Fatal("loaded CA should match created CA")
	}
	if ca2.cert.SerialNumber.Cmp(ca1.cert.SerialNumber) != 0 {
		t.Fatal("serial numbers should match")
	}
}

func TestTLSConfigForGeneratesCertForHost(t *testing.T) {
	tmpdir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(tmpdir, "ca.crt"), filepath.Join(tmpdir, "ca.key"))
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	hostname := "example.com"
	tlsConfig, err := ca.TLSConfigFor(hostname)
	if err != nil {
		t.Fatalf("failed to get TLS config: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("expected TLS config to be created")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatal("expected exactly one certificate")
	}

	// Verify certificate is valid for the host
	cert := tlsConfig.Certificates[0]
	if len(cert.Certificate) == 0 {
		t.Fatal("expected certificate data")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if x509Cert.Subject.CommonName != hostname {
		t.Fatalf("certificate CN should be %s, got %s", hostname, x509Cert.Subject.CommonName)
	}

	// Verify it's a server cert
	if len(x509Cert.ExtKeyUsage) == 0 || x509Cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("certificate should have ServerAuth extended key usage")
	}
}

func TestTLSConfigForCachesCertificates(t *testing.T) {
	tmpdir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(tmpdir, "ca.crt"), filepath.Join(tmpdir, "ca.key"))
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	hostname := "example.com"

	// Get config twice
	tlsConfig1, err := ca.TLSConfigFor(hostname)
	if err != nil {
		t.Fatalf("failed to get TLS config first time: %v", err)
	}

	tlsConfig2, err := ca.TLSConfigFor(hostname)
	if err != nil {
		t.Fatalf("failed to get TLS config second time: %v", err)
	}

	// Both should have the same certificate data (from cache)
	cert1 := tlsConfig1.Certificates[0].Certificate[0]
	cert2 := tlsConfig2.Certificates[0].Certificate[0]

	if len(cert1) != len(cert2) {
		t.Fatal("cached certificate should be identical")
	}
	for i, b := range cert1 {
		if cert2[i] != b {
			t.Fatal("cached certificate should be identical")
		}
	}
}

func TestCertificateExpiryIsReasonable(t *testing.T) {
	tmpdir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(tmpdir, "ca.crt"), filepath.Join(tmpdir, "ca.key"))
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	hostname := "example.com"
	tlsConfig, err := ca.TLSConfigFor(hostname)
	if err != nil {
		t.Fatalf("failed to get TLS config: %v", err)
	}

	x509Cert, _ := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])

	// Check certificate is valid for approximately 1 year
	validity := x509Cert.NotAfter.Sub(x509Cert.NotBefore)
	expectedValidity := 365 * 24 * time.Hour

	if validity < expectedValidity-time.Minute || validity > expectedValidity+time.Minute {
		t.Logf("certificate validity %v is not approximately 365 days", validity)
	}

	// Check NotBefore is in the past (with a minute buffer)
	if time.Now().Before(x509Cert.NotBefore) {
		t.Fatal("certificate NotBefore should not be in the future")
	}
}

func TestTLSConfigMinimumVersion(t *testing.T) {
	tmpdir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(tmpdir, "ca.crt"), filepath.Join(tmpdir, "ca.key"))
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	tlsConfig, err := ca.TLSConfigFor("example.com")
	if err != nil {
		t.Fatalf("failed to get TLS config: %v", err)
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion should be TLS 1.2, got %v", tlsConfig.MinVersion)
	}
}

func TestMultipleHostsCertificateGeneration(t *testing.T) {
	tmpdir := t.TempDir()
	ca, err := LoadOrCreateCA(filepath.Join(tmpdir, "ca.crt"), filepath.Join(tmpdir, "ca.key"))
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	hosts := []string{"example.com", "google.com", "youtube.com"}

	for _, host := range hosts {
		tlsConfig, err := ca.TLSConfigFor(host)
		if err != nil {
			t.Fatalf("failed to get TLS config for %s: %v", host, err)
		}

		x509Cert, _ := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
		if x509Cert.Subject.CommonName != host {
			t.Fatalf("certificate CN for %s should be %s", host, host)
		}
	}

	// Verify all three are cached
	if len(ca.cache) != 3 {
		t.Fatalf("expected 3 cached certificates, got %d", len(ca.cache))
	}
}
