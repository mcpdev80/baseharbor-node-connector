package targetaccess

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapConfigRequiresHTTPSAndPinnedIdentity(t *testing.T) {
	cfg := BootstrapConfig{
		EnrollmentURL:          "http://core.example/enroll",
		TrustBundleFile:        "ca.pem",
		TokenFile:              "token",
		ExpectedServerIdentity: "spiffe://baseharbor/core/bootstrap",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("plain HTTP bootstrap unexpectedly accepted")
	}
	cfg.EnrollmentURL = "https://core.example/enroll"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapDestinationRejectsCredentialAndAmbiguousURLs(t *testing.T) {
	for _, destination := range []string{
		"https://user:password@core.example/enroll",
		"https://core.example/enroll?token=secret",
		"https://core.example/enroll#other",
		"https:core.example/enroll",
	} {
		cfg := BootstrapConfig{EnrollmentURL: destination, TrustBundleFile: "ca.pem",
			TokenFile: "token", ExpectedServerIdentity: "spiffe://baseharbor/core/bootstrap"}
		if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), destination) {
			t.Fatal("unsafe enrollment URL accepted or echoed")
		}
	}
}

func TestReadBootstrapTokenRequiresPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapToken(path); err == nil {
		t.Fatal("group/world-readable bootstrap token unexpectedly accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readBootstrapToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if value != "secret" {
		t.Fatalf("token = %q", value)
	}
}

func TestCreateEnrollmentCSRBindsNodeURIIdentity(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := "spiffe://baseharbor/target/edge-a/node/node-1"
	csrPEM, err := createEnrollmentCSR(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("CSR PEM missing")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != identity {
		t.Fatalf("CSR identities = %#v", csr.URIs)
	}
}

func TestValidateEnrollmentBindingRejectsCrossTargetResponse(t *testing.T) {
	expected := NodeIdentity{NodeID: "node-1", TargetID: "edge-a", Runtime: "docker", Identity: "spiffe://baseharbor/target/edge-a/node/node-1"}
	actual := expected
	actual.TargetID = "edge-b"
	if err := validateEnrollmentBinding(expected, actual); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("cross-target enrollment response unexpectedly accepted: %v", err)
	}
}

func TestEnsureEnrollmentPrivateKeyCreatesPrivateKeyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity", "node.key")
	if err := EnsureEnrollmentPrivateKey(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o", info.Mode().Perm())
	}
	if err := EnsureEnrollmentPrivateKey(path); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("existing enrollment private key was replaced")
	}
}
