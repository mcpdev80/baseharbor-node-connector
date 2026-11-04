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

func TestRevocationFileRejectsInvalidEntriesAndPaddedSerials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.txt")
	files := TLSFiles{RevokedSerialsFile: path}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(42)}
	for _, entry := range []string{"garbage", "0x", "12xz", "0xGG"} {
		if err := os.WriteFile(path, []byte(entry), 0600); err != nil {
			t.Fatal(err)
		}
		if err := files.verifyNotRevoked(certificate); err == nil {
			t.Fatalf("invalid revocation entry %q was accepted", entry)
		}
	}
	if err := os.WriteFile(path, []byte("0x002a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := files.verifyNotRevoked(certificate); err == nil {
		t.Fatal("revoked certificate with zero-padded serial was accepted")
	}
}

func TestTLSClientCertificateIsReloadedAfterRotation(t *testing.T) {
	ca, key, trust := newTestCA(t)
	const identity = "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"
	first := newTestLeaf(t, ca, key, trust, identity, big.NewInt(41))
	second := newTestLeaf(t, ca, key, trust, identity, big.NewInt(42))
	files := TLSFiles{CertificateFile: first.certPath, PrivateKeyFile: first.keyPath,
		TrustBundleFile: first.caPath, ExpectedPeerIdentity: identity}
	config, err := files.Config(TLSClient)
	if err != nil {
		t.Fatal(err)
	}
	before, err := config.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{second.certPath, first.certPath}, {second.keyPath, first.keyPath}} {
		content, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pair[1], content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	after, err := config.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Certificate) == 0 || len(after.Certificate) == 0 {
		t.Fatal("rotated client certificate was not loaded")
	}
	if string(before.Certificate[0]) == string(after.Certificate[0]) {
		t.Fatal("TLS configuration continued to use the retired client certificate")
	}
}
