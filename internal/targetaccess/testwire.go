package targetaccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// randLeafSerial produces a leaf serial distinct from the CA (serial 1) so the
// CA->leaf chain satisfies RFC 5280 uniqueness that Go's x509 verifier enforces.
func randLeafSerial() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<20))
	if err != nil {
		return 2
	}
	return n.Int64() + 1
}

// HandshakeMaterial is one side of a test handshake pair: the on-disk TLS
// material produced by the same ephemeral ceremony the package tests already
// use, now exported behind a single call so package-external tests (e.g. the
// connector package) can build a real mTLS handshake pair over any net.Conn.
//
// This is test infrastructure only. It moves the existing newTestCA/newTestLeaf
// construction out of the sealed _test.go files and wraps it behind an exported
// constructor. It does not change any product API surface, does not touch
// OpenSession, and produces only ephemeral, in-memory or t.TempDir-scoped
// material.
type HandshakeMaterial struct {
	CertificateFile string
	PrivateKeyFile  string
	TrustBundleFile string
	Identity        string
}

// HandshakePair is a CA-signed server/client pair for a real target-access
// mTLS handshake. Each side is built from the SAME ceremony the package tests
// already use (a fresh ECDSA P-256 CA signing fresh P-256 leaf certs), but the
// pair is exposed so it can be imported from outside the targetaccess package.
type HandshakePair struct {
	Leaf map[string]HandshakeMaterial
}

// NewHandshakePair builds a real, self-contained mTLS handshake pair from the
// same ephemeral ceremony the internal tests already use. caIdentity is the CA
// subject; serverIdentity and clientIdentity are the two leaf SPIFFE identities
// that will authenticate against each other. Callers pass the returned pairs
// into OpenSession with TLSClient/TLSServer roles; the ExpectedPeerIdentity of
// each side is the other side's identity.
func NewHandshakePair(t *testing.T, caIdentity, serverIdentity, clientIdentity string) *HandshakePair {
	t.Helper()
	pair := &HandshakePair{Leaf: map[string]HandshakeMaterial{}}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: caIdentity},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pair.Leaf["server"] = newTestLeafMaterial(t, caCert, caKey, caPEM, serverIdentity)
	pair.Leaf["client"] = newTestLeafMaterial(t, caCert, caKey, caPEM, clientIdentity)
	return pair
}

// newTestLeafMaterial is the shared, non-test ceremony that builds one CA-signed
// leaf side from ephemeral P-256 material into a t.TempDir-scoped set of PEM
// files. It replaces the per-test copies that lived sealed inside _test.go; the
// package's own tests now delegate to it (one-line delegation, behavior
// unchanged). Kept in a non-test file so it can be imported by external smoke
// tests behind the exported NewHandshakePair surface.
func newTestLeafMaterial(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte, identity string) HandshakeMaterial {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(identity)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(randLeafSerial()),
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return HandshakeMaterial{
		CertificateFile: certPath,
		PrivateKeyFile:  keyPath,
		TrustBundleFile: caPath,
		Identity:        identity,
	}
}
