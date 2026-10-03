package targetaccess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testTLSMaterial struct {
	certPath string
	keyPath  string
	caPath   string
	identity string
}

func TestOpenSessionMutualTLSNegotiationAndRequestFrame(t *testing.T) {
	caCert, caKey, caPEM := newTestCA(t)
	core := newTestLeaf(t, caCert, caKey, caPEM, "spiffe://baseharbor/core/control-plane", big.NewInt(2))
	node := newTestLeaf(t, caCert, caKey, caPEM, "spiffe://baseharbor/node/node-a", big.NewInt(3))

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverHello := Hello{
		ContractVersions: []string{ContractVersion},
		ProtocolVersions: []string{ProtocolVersion},
		Node: NodeIdentity{
			NodeID: "node-a", TargetID: "target-a", Runtime: "docker", Identity: node.identity,
		},
	}
	clientHello := Hello{
		ContractVersions: []string{ContractVersion},
		ProtocolVersions: []string{ProtocolVersion},
		Node: NodeIdentity{
			NodeID: "core", TargetID: "target-a", Runtime: "docker", Identity: core.identity,
		},
	}

	type result struct {
		session *Session
		err     error
	}
	serverResult := make(chan result, 1)
	go func() {
		session, err := OpenSession(ctx, serverConn, TLSServer, TLSFiles{
			CertificateFile: node.certPath,
			PrivateKeyFile: node.keyPath,
			TrustBundleFile: node.caPath,
			ExpectedPeerIdentity: core.identity,
		}, serverHello, 0)
		serverResult <- result{session: session, err: err}
	}()

	clientSession, err := OpenSession(ctx, clientConn, TLSClient, TLSFiles{
		CertificateFile: core.certPath,
		PrivateKeyFile: core.keyPath,
		TrustBundleFile: core.caPath,
		ExpectedPeerIdentity: node.identity,
	}, clientHello, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	server := <-serverResult
	if server.err != nil {
		t.Fatal(server.err)
	}
	defer server.session.Close()

	if clientSession.Negotiated.Node.Identity != node.identity {
		t.Fatalf("client negotiated wrong node identity: %#v", clientSession.Negotiated.Node)
	}
	if server.session.Negotiated.Node.Identity != core.identity {
		t.Fatalf("server negotiated wrong core identity: %#v", server.session.Negotiated.Node)
	}

	request := Request{
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		RequestID: "req-1",
		CorrelationID: "corr-1",
		TargetID: "target-a",
		Operation: OpCapabilities,
		IssuedAt: time.Now().UTC(),
	}
	readResult := make(chan error, 1)
	go func() {
		var got Request
		if err := server.session.ReadRequest(&got); err != nil {
			readResult <- err
			return
		}
		if got.RequestID != request.RequestID || got.Operation != OpCapabilities {
			readResult <- errUnexpectedRequest{}
			return
		}
		readResult <- nil
	}()
	if err := clientSession.WriteRequest(request); err != nil {
		t.Fatal(err)
	}
	if err := <-readResult; err != nil {
		t.Fatal(err)
	}
}

type errUnexpectedRequest struct{}

func (errUnexpectedRequest) Error() string { return "unexpected target-access request" }

func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "BaseHarbor Test CA"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
		IsCA: true,
		BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte, identity string, serial *big.Int) testTLSMaterial {
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
		SerialNumber: serial,
		Subject: pkix.Name{CommonName: identity},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		URIs: []*url.URL{uri},
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
	return testTLSMaterial{certPath: certPath, keyPath: keyPath, caPath: caPath, identity: identity}
}
