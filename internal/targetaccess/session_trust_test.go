package targetaccess

import (
	"context"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func currentTrustSession(t *testing.T) (*Session, TLSFiles) {
	t.Helper()
	ca, key, trust := newTestCA(t)
	core := newTestLeaf(t, ca, key, trust, "spiffe://baseharbor/platform/core/test", big.NewInt(2))
	node := newTestLeaf(t, ca, key, trust, "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a", big.NewInt(3))
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	local := Hello{ContractVersions: []string{ContractVersion}, ProtocolVersions: []string{ProtocolVersion},
		Node: NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111", TargetID: "target-a", NodeID: "node-a", Runtime: "docker", Identity: node.identity}}
	remote := local
	remote.Node.NodeID, remote.Node.Identity = "core", core.identity
	nodeFiles := TLSFiles{CertificateFile: node.certPath, PrivateKeyFile: node.keyPath,
		TrustBundleFile: node.caPath, ExpectedPeerIdentity: core.identity, RevokedSerialsFile: filepath.Join(t.TempDir(), "revoked")}
	if err := os.WriteFile(nodeFiles.RevokedSerialsFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	coreFiles := TLSFiles{CertificateFile: core.certPath, PrivateKeyFile: core.keyPath,
		TrustBundleFile: core.caPath, ExpectedPeerIdentity: node.identity}
	type result struct {
		session *Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		session, err := OpenSession(ctx, left, TLSServer, coreFiles, remote, 0)
		accepted <- result{session, err}
	}()
	session, err := OpenSession(ctx, right, TLSClient, nodeFiles, local, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-accepted
	if peer.err != nil {
		t.Fatal(peer.err)
	}
	t.Cleanup(func() { _ = session.Close(); _ = peer.session.Close() })
	return session, nodeFiles
}

func TestOpenSessionTrustRemovalBlocksFramesBeforeWrite(t *testing.T) {
	session, files := currentTrustSession(t)
	_, _, newTrust := newTestCA(t)
	if err := os.WriteFile(files.TrustBundleFile, newTrust, 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := Request{ContractVersion: ContractVersion, ProtocolVersion: ProtocolVersion,
		RequestID: "retired-core", CorrelationID: "execution-retired", TargetID: "target-a",
		Operation: OpCapabilities, IssuedAt: now, DeadlineAt: now.Add(time.Second), Payload: []byte(`{}`)}
	if err := session.WriteRequest(request); err == nil || session.Context().Err() == nil {
		t.Fatal("cached TLS handshake accepted a retired peer CA")
	}
}

func TestIdleSessionTrustFailureAndRevocationCloseWithinBound(t *testing.T) {
	for _, mode := range []string{"retired-ca", "missing-trust", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			session, files := currentTrustSession(t)
			switch mode {
			case "retired-ca":
				_, _, newTrust := newTestCA(t)
				if err := os.WriteFile(files.TrustBundleFile, newTrust, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-trust":
				if err := os.Remove(files.TrustBundleFile); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				if err := os.WriteFile(files.RevokedSerialsFile, []byte("2\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-session.Context().Done():
			case <-time.After(8 * time.Second):
				t.Fatal("idle peer retirement exceeded trust check bound")
			}
		})
	}
}
