package targetaccess

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type TLSRole string

const (
	TLSClient TLSRole = "client"
	TLSServer TLSRole = "server"
)

type TLSFiles struct {
	CertificateFile      string
	PrivateKeyFile       string
	TrustBundleFile      string
	ExpectedPeerIdentity string
	ServerName           string
}

func (f TLSFiles) Validate() error {
	for name, value := range map[string]string{
		"certificate_file": f.CertificateFile,
		"private_key_file":  f.PrivateKeyFile,
		"trust_bundle_file": f.TrustBundleFile,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if strings.TrimSpace(f.ExpectedPeerIdentity) == "" {
		return errors.New("expected_peer_identity is required")
	}
	return nil
}

func (f TLSFiles) Config(role TLSRole) (*tls.Config, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	if role != TLSClient && role != TLSServer {
		return nil, fmt.Errorf("unsupported TLS role %q", role)
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: strings.TrimSpace(f.ServerName),
	}

	loadCertificate := func() (tls.Certificate, error) {
		return tls.LoadX509KeyPair(f.CertificateFile, f.PrivateKeyFile)
	}
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := loadCertificate()
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := loadCertificate()
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}

	if role == TLSServer {
		cfg.ClientAuth = tls.RequireAnyClientCert
	} else {
		cfg.InsecureSkipVerify = true
	}

	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		return f.verifyConnection(role, state)
	}
	return cfg, nil
}

func (f TLSFiles) verifyConnection(role TLSRole, state tls.ConnectionState) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("peer did not present a certificate")
	}
	roots, err := loadCertPool(f.TrustBundleFile)
	if err != nil {
		return err
	}
	leaf := state.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	dnsName := ""
	if role == TLSClient {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		dnsName = strings.TrimSpace(f.ServerName)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     usages,
		DNSName:       dnsName,
		CurrentTime:   time.Now(),
	}); err != nil {
		return fmt.Errorf("verify peer certificate: %w", err)
	}
	return verifyPeerIdentity(leaf, f.ExpectedPeerIdentity)
}

func verifyPeerIdentity(cert *x509.Certificate, expected string) error {
	expected = strings.TrimSpace(expected)
	for _, uri := range cert.URIs {
		if uri.String() == expected {
			return nil
		}
	}
	for _, dns := range cert.DNSNames {
		if dns == expected {
			return nil
		}
	}
	if parsed, err := url.Parse(expected); err == nil && parsed.Scheme != "" {
		return fmt.Errorf("peer identity %q is not present in certificate URI SANs", expected)
	}
	return fmt.Errorf("peer identity %q is not present in certificate SANs", expected)
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trust bundle: %w", err)
	}
	pool := x509.NewCertPool()
	rest := data
	var count int
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse trust certificate: %w", err)
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return nil, errors.New("trust bundle contains no certificates")
	}
	return pool, nil
}
