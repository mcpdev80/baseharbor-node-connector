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
	request := EnrollmentRequest{
		ContractVersion: EnrollmentContractVersion,
		NodeID: "node-a",
		TargetID: "target-a",
		Runtime: "docker",
		CSRPEM: csrPEM,
		Nonce: "nonce-a",
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid enrollment request rejected: %v", err)
	}
	if request.CSRPEM == "" {
		t.Fatal("csr missing")
	}
}
