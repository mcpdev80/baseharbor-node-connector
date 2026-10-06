package targetaccess

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestEnrollmentRequestAcceptsSignedCSRAndCarriesNoPrivateKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	request := EnrollmentRequest{TenantID: "11111111-1111-4111-8111-111111111111",
		ContractVersion: EnrollmentContractVersion,
		NodeID:          "node-a",
		TargetID:        "target-a",
		Runtime:         "docker",
		CSRPEM:          csrPEM,
		Nonce:           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid enrollment request rejected: %v", err)
	}
	if request.CSRPEM == "" {
		t.Fatal("csr missing")
	}
}

func TestEnrollmentCSRRejectsAmbiguousPEM(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw}))
	for _, material := range []string{csr + csr, "SECRET\n" + csr, csr + "SECRET"} {
		request := EnrollmentRequest{TenantID: "11111111-1111-4111-8111-111111111111", ContractVersion: EnrollmentContractVersion, NodeID: "node-a", TargetID: "target-a", Runtime: "docker", Nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", CSRPEM: material}
		if err := request.Validate(); err == nil {
			t.Fatal("ambiguous CSR accepted")
		}
	}
}
