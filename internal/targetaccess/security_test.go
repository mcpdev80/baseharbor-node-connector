package targetaccess

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"
)

func TestVerifyPeerIdentityUsesExplicitSANIdentity(t *testing.T) {
	uri, err := url.Parse("spiffe://baseharbor/node/node-a")
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		URIs:     []*url.URL{uri},
		DNSNames: []string{"node-a.example"},
	}
	if err := verifyPeerIdentity(cert, "spiffe://baseharbor/node/node-a"); err != nil {
		t.Fatalf("URI identity rejected: %v", err)
	}
	if err := verifyPeerIdentity(cert, "node-a.example"); err != nil {
		t.Fatalf("DNS identity rejected: %v", err)
	}
	if err := verifyPeerIdentity(cert, "spiffe://baseharbor/node/node-b"); err == nil {
		t.Fatal("wrong URI identity unexpectedly accepted")
	}
}

func TestTLSFilesRequireExplicitPeerIdentityAndTLS13(t *testing.T) {
	files := TLSFiles{
		CertificateFile: "node.crt",
		PrivateKeyFile:  "node.key",
		TrustBundleFile: "ca.pem",
	}
	if err := files.Validate(); err == nil {
		t.Fatal("missing expected peer identity unexpectedly accepted")
	}
	files.ExpectedPeerIdentity = "spiffe://baseharbor/core/control-plane"
	cfg, err := files.Config(TLSServer)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("minimum TLS version = %#x, want TLS 1.3", cfg.MinVersion)
	}
}
