package targetaccess

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBootstrapConfigRequiresHTTPSAndPinnedIdentity(t *testing.T) {
	cfg := BootstrapConfig{
		EnrollmentURL:          "http://core.example/enroll",
		TrustBundleFile:        "ca.pem",
		AuthorizationFile:      "token",
		ExpectedServerIdentity: "spiffe://baseharbor/platform/core/bootstrap",
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
			AuthorizationFile: "token", ExpectedServerIdentity: "spiffe://baseharbor/platform/core/bootstrap"}
		if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), destination) {
			t.Fatal("unsafe enrollment URL accepted or echoed")
		}
	}
}

func TestReadBootstrapAuthorizationBindsCoreNonceAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "authorization.json")
	expected := BootstrapAuthorization{Token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Nonce: "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ", ExpiresAt: now.Add(time.Minute)}
	data, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapAuthorization(path, now); err == nil {
		t.Fatal("public authorization accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	actual, err := readBootstrapAuthorization(path, now)
	if err != nil || actual.Token != expected.Token || actual.Nonce != expected.Nonce || !actual.ExpiresAt.Equal(expected.ExpiresAt) {
		t.Fatalf("Core authorization changed: %v", err)
	}
	for _, bad := range []string{"secret", string(data) + string(data), strings.Replace(string(data), `"token":`, `"SECRET-CREDENTIAL":"hidden","token":`, 1), strings.Replace(string(data), expected.Nonce, "nonce-generated-locally", 1)} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBootstrapAuthorization(path, now); err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "hidden") {
			t.Fatalf("invalid credential accepted or echoed: %v", err)
		}
	}
	for _, expiry := range []time.Time{now.Add(-time.Second), now.Add(time.Hour)} {
		expected.ExpiresAt = expiry
		data, _ = json.Marshal(expected)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBootstrapAuthorization(path, now); err == nil {
			t.Fatal("expired or unbounded grant accepted")
		}
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBootstrapAuthorization(link, now); err == nil {
		t.Fatal("symlink authorization accepted")
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
	identity := "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/edge-a/node-1"
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
	expected := NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111", NodeID: "node-1", TargetID: "edge-a", Runtime: "docker", Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/edge-a/node-1"}
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
