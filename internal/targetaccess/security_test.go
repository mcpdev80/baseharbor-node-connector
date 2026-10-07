package targetaccess

import (
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyPeerIdentityUsesExplicitSANIdentity(t *testing.T) {
	uri, err := url.Parse("spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a")
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		URIs:     []*url.URL{uri},
		DNSNames: []string{"node-a.example"},
	}
	if err := verifyPeerIdentity(cert, "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"); err != nil {
		t.Fatalf("URI identity rejected: %v", err)
	}
	if err := verifyPeerIdentity(cert, "node-a.example"); err != nil {
		t.Fatalf("DNS identity rejected: %v", err)
	}
	if err := verifyPeerIdentity(cert, "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-b"); err == nil {
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
	files.ExpectedPeerIdentity = "spiffe://baseharbor/platform/core/control-plane"
	cfg, err := files.Config(TLSServer)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("minimum TLS version = %#x, want TLS 1.3", cfg.MinVersion)
	}
}

func TestTLSFilesRejectRevokedSerialFromReloadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.txt")
	if err := os.WriteFile(path, []byte("2a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	files := TLSFiles{RevokedSerialsFile: path}
	cert := &x509.Certificate{SerialNumber: big.NewInt(0x2a)}
	if err := files.verifyNotRevoked(cert); err == nil {
		t.Fatal("revoked certificate unexpectedly accepted")
	}

	if err := os.WriteFile(path, []byte("# rotated revocation set\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := files.verifyNotRevoked(cert); err != nil {
		t.Fatalf("reloaded revocation file did not take effect: %v", err)
	}
}
