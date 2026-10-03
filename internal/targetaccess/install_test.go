package targetaccess

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInstallEnrollmentBindsCertificateToLocalPrivateKey(t *testing.T) {
	caCert, caKey, caPEM := newTestCA(t)
	node := newTestLeaf(t, caCert, caKey, caPEM, "spiffe://baseharbor/node/node-a", big.NewInt(10))

	certPEM, err := os.ReadFile(node.certPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := TLSFiles{
		CertificateFile: filepath.Join(dir, "identity", "node.crt"),
		PrivateKeyFile: node.keyPath,
		TrustBundleFile: filepath.Join(dir, "identity", "ca.pem"),
		ExpectedPeerIdentity: "spiffe://baseharbor/core/control-plane",
	}
	response := EnrollmentResponse{
		ContractVersion: EnrollmentContractVersion,
		Node: NodeIdentity{
			NodeID: "node-a", TargetID: "target-a", Runtime: "docker",
			Identity: node.identity,
		},
		CertificatePEM: string(certPEM),
		TrustBundlePEM: string(caPEM),
		NotAfter: time.Now().Add(30 * time.Minute),
	}
	if err := InstallEnrollment(files, response, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files.CertificateFile); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files.TrustBundleFile); err != nil {
		t.Fatal(err)
	}
}
