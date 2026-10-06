package targetaccess

import (
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInstallEnrollmentBindsCertificateToLocalPrivateKey(t *testing.T) {
	caCert, caKey, caPEM := newTestCA(t)
	node := newTestLeaf(t, caCert, caKey, caPEM, "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a", big.NewInt(10), x509.ExtKeyUsageClientAuth)

	certPEM, err := os.ReadFile(node.certPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := TLSFiles{
		CertificateFile:      filepath.Join(dir, "identity", "node.crt"),
		PrivateKeyFile:       node.keyPath,
		TrustBundleFile:      filepath.Join(dir, "identity", "ca.pem"),
		ExpectedPeerIdentity: "spiffe://baseharbor/platform/core/control-plane",
	}
	response := EnrollmentResponse{Nonce:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ContractVersion: EnrollmentContractVersion,
		Node: NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111",
			NodeID: "node-a", TargetID: "target-a", Runtime: "docker",
			Identity: node.identity,
		},
		CertificatePEM: string(certPEM),
		TrustBundlePEM: string(caPEM),
		NotAfter: func() time.Time {
			cert, err := firstCertificate(certPEM)
			if err != nil {
				t.Fatal(err)
			}
			return cert.NotAfter
		}(),
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

func TestInstallEnrollmentRejectsServerAndAmbiguousPublicMaterial(t *testing.T) {
	caCert, caKey, caPEM := newTestCA(t)
	for _, variant := range []string{"server", "dual-purpose", "extra-leaf", "leading-material", "trailing-trust", "leaf-as-trust", "expiry"} {
		t.Run(variant, func(t *testing.T) {
			usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			if variant == "server" {
				usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			}
			if variant == "dual-purpose" {
				usages = append(usages, x509.ExtKeyUsageServerAuth)
			}
			node := newTestLeaf(t, caCert, caKey, caPEM, "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a", big.NewInt(20), usages...)
			certPEM, err := os.ReadFile(node.certPath)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := firstCertificate(certPEM)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			files := TLSFiles{PrivateKeyFile: node.keyPath, CertificateFile: filepath.Join(dir, "node.crt"), TrustBundleFile: filepath.Join(dir, "ca.pem")}
			response := EnrollmentResponse{Nonce:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",ContractVersion: EnrollmentContractVersion, Node: NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111",NodeID: "node-a", TargetID: "target-a", Runtime: "docker", Identity: node.identity}, CertificatePEM: string(certPEM), TrustBundlePEM: string(caPEM), NotAfter: cert.NotAfter}
			switch variant {
			case "extra-leaf":
				response.CertificatePEM += string(certPEM)
			case "leading-material":
				response.CertificatePEM = "SECRET\n" + response.CertificatePEM
			case "trailing-trust":
				response.TrustBundlePEM += "SECRET"
			case "leaf-as-trust":
				response.TrustBundlePEM = string(certPEM)
			case "expiry":
				response.NotAfter = response.NotAfter.Add(-time.Second)
			}
			if err := InstallEnrollment(files, response, time.Now()); err == nil {
				t.Fatal("invalid enrollment material installed")
			}
			if _, err := os.Stat(files.CertificateFile); !os.IsNotExist(err) {
				t.Fatal("rejected certificate changed identity files")
			}
		})
	}
}
