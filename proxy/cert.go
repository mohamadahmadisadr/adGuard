package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"sync"
	"time"
)

// CA holds the root certificate and key used to sign per-host certificates.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	tlsCert tls.Certificate

	mu    sync.Mutex
	cache map[string]*tls.Certificate // host → signed cert
}

// LoadOrCreateCA loads ca.crt/ca.key from disk, creating them if absent.
// Install ca.crt as a trusted root CA on every device that will use this proxy.
func LoadOrCreateCA(certFile, keyFile string) (*CA, error) {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		return createCA(certFile, keyFile)
	}
	return loadCA(certFile, keyFile)
}

func createCA(certFile, keyFile string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dns-proxy CA", Organization: []string{"dns-proxy"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// Write cert
	cf, err := os.Create(certFile)
	if err != nil {
		return nil, err
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return nil, err
	}

	// Write key
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	kf, err := os.Create(keyFile)
	if err != nil {
		return nil, err
	}
	defer kf.Close()
	if err := pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}); err != nil {
		return nil, err
	}

	return buildCA(der, key)
}

func loadCA(certFile, keyFile string) (*CA, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	key := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	return &CA{cert: cert, key: key, tlsCert: tlsCert, cache: make(map[string]*tls.Certificate)}, nil
}

func buildCA(der []byte, key *ecdsa.PrivateKey) (*CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &CA{cert: cert, key: key, tlsCert: tlsCert, cache: make(map[string]*tls.Certificate)}, nil
}

// TLSConfigFor returns a *tls.Config with a certificate signed for host.
// Results are cached so we only generate each host cert once.
func (ca *CA) TLSConfigFor(host string) (*tls.Config, error) {
	ca.mu.Lock()
	if c, ok := ca.cache[host]; ok {
		ca.mu.Unlock()
		return &tls.Config{Certificates: []tls.Certificate{*c}, MinVersion: tls.VersionTLS12}, nil
	}
	ca.mu.Unlock()

	c, err := ca.signHost(host)
	if err != nil {
		return nil, err
	}

	ca.mu.Lock()
	ca.cache[host] = c
	ca.mu.Unlock()

	return &tls.Config{Certificates: []tls.Certificate{*c}, MinVersion: tls.VersionTLS12}, nil
}

func (ca *CA) signHost(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}

	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return c, nil
}
