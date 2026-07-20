package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// caCertFile and caKeyFile hold the root CA, persisted next to the
// executable (same convention config.go uses for config.json). This has to
// survive restarts: it's what the user installs as a trusted root on their
// phone, and regenerating it on every run would mean re-installing it every
// time too.
const (
	caCertFile = "mitm-ca-cert.pem"
	caKeyFile  = "mitm-ca-key.pem"
)

// certAuthority signs per-host leaf certificates on demand, caching them in
// memory (cheap to regenerate, unlike the root CA — nothing external trusts
// a leaf cert directly, so there's no reason to persist them).
type certAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// loadOrCreateCA loads the root CA from disk next to the executable, or
// generates and persists a new one if it doesn't exist yet.
func loadOrCreateCA() (*certAuthority, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locate executable: %w", err)
	}
	dir := filepath.Dir(exePath)
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			ca, err := loadCA(certPath, keyPath)
			if err != nil {
				return nil, fmt.Errorf("load existing CA: %w", err)
			}
			fmt.Println("Loaded existing MITM CA from", certPath)
			return ca, nil
		}
	}

	ca, err := generateCA(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}
	fmt.Println("Generated new MITM CA at", certPath, "- install this on clients to intercept HTTPS")
	return ca, nil
}

// generateCA creates a new self-signed root CA and writes it (cert and key,
// both PEM-encoded) to certPath/keyPath.
func generateCA(certPath, keyPath string) (*certAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "shmitm MITM CA",
			Organization: []string{"shmitm"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return nil, fmt.Errorf("write CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key: %w", err)
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse freshly created CA certificate: %w", err)
	}

	return &certAuthority{cert: cert, key: key, cache: make(map[string]*tls.Certificate)}, nil
}

// loadCA reads a previously generated CA back from certPath/keyPath.
func loadCA(certPath, keyPath string) (*certAuthority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("%s: not a valid PEM file", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("%s: not a valid PEM file", keyPath)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	return &certAuthority{cert: cert, key: key, cache: make(map[string]*tls.Certificate)}, nil
}

// certFor returns a leaf certificate for host, signed by the CA, generating
// and caching one on first request. host may be a DNS name (the common
// case, from a ClientHello's SNI) or an IP address.
func (ca *certAuthority) certFor(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if cert, ok := ca.cache[host]; ok {
		return cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %q: %w", host, err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate for %q: %w", host, err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{leafDER, ca.cert.Raw},
		PrivateKey:  key,
	}
	ca.cache[host] = cert
	return cert, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
