package connector

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

// TestServeLogStreamHandshakeWireRoundTrip is the red-first/green proof for
// t-20261105-r27-test-wire-helper: an external package (connector) imports the
// exported targetaccess handshake helper, builds a real mTLS handshake pair over
// a real net.Pipe line, negotiates a session via the real OpenSession path, and
// round-trips one frame through that secured line. Without the helper this test
// does not compile (the ceremony was sealed inside _test.go); with it, the frame
// crosses the wire.
func TestServeLogStreamHandshakeWireRoundTrip(t *testing.T) {
	const (
		tenant     = "11111111-1111-4111-8111-111111111111"
		serverID   = "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"
		clientID   = "spiffe://baseharbor/platform/core/control-plane"
		targetName = "target-a"
	)

	pair := targetaccess.NewHandshakePair(t, "BaseHarbor Test CA", serverID, clientID)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serverHello := targetaccess.Hello{
		ContractVersions: []string{targetaccess.ContractVersion},
		ProtocolVersions: []string{targetaccess.ProtocolVersion},
		Node: targetaccess.NodeIdentity{
			TenantID: tenant, NodeID: "node-a", TargetID: targetName,
			Runtime: "docker", Identity: serverID,
		},
	}
	clientHello := targetaccess.Hello{
		ContractVersions: []string{targetaccess.ContractVersion},
		ProtocolVersions: []string{targetaccess.ProtocolVersion},
		Node: targetaccess.NodeIdentity{
			TenantID: tenant, NodeID: "core", TargetID: targetName,
			Runtime: "docker", Identity: clientID,
		},
	}

	type outcome struct {
		session *targetaccess.Session
		err     error
	}
	serverDone := make(chan outcome, 1)
	go func() {
		sess, err := targetaccess.OpenSession(ctx, serverConn, targetaccess.TLSServer, targetaccess.TLSFiles{
			CertificateFile:      pair.Leaf["server"].CertificateFile,
			PrivateKeyFile:       pair.Leaf["server"].PrivateKeyFile,
			TrustBundleFile:      pair.Leaf["server"].TrustBundleFile,
			ExpectedPeerIdentity: clientID,
		}, serverHello, 0)
		serverDone <- outcome{session: sess, err: err}
	}()

	clientSession, err := targetaccess.OpenSession(ctx, clientConn, targetaccess.TLSClient, targetaccess.TLSFiles{
		CertificateFile:      pair.Leaf["client"].CertificateFile,
		PrivateKeyFile:       pair.Leaf["client"].PrivateKeyFile,
		TrustBundleFile:      pair.Leaf["client"].TrustBundleFile,
		ExpectedPeerIdentity: serverID,
	}, clientHello, 0)
	if err != nil {
		t.Fatalf("client OpenSession over real mTLS line failed: %v", err)
	}
	defer clientSession.Close()

	server := <-serverDone
	if server.err != nil {
		t.Fatalf("server OpenSession over real mTLS line failed: %v", server.err)
	}
	defer server.session.Close()

	if clientSession.Negotiated.Node.Identity != serverID {
		t.Fatalf("client negotiated wrong peer identity: %#v", clientSession.Negotiated.Node)
	}
	if server.session.Negotiated.Node.Identity != clientID {
		t.Fatalf("server negotiated wrong peer identity: %#v", server.session.Negotiated.Node)
	}

	request := targetaccess.Request{
		ContractVersion: targetaccess.ContractVersion,
		ProtocolVersion: targetaccess.ProtocolVersion,
		RequestID:       "req-wire-1",
		CorrelationID:   "corr-wire-1",
		TargetID:        targetName,
		Operation:       targetaccess.OpCapabilities,
		Payload:         json.RawMessage("{}"),
		IssuedAt:        time.Now().UTC(),
		DeadlineAt:      time.Now().UTC().Add(5 * time.Minute),
	}
	frameDone := make(chan targetaccess.Request, 1)
	go func() {
		var got targetaccess.Request
		if err := server.session.ReadRequest(&got); err != nil {
			frameDone <- targetaccess.Request{}
			return
		}
		frameDone <- got
	}()

	if err := clientSession.WriteRequest(request); err != nil {
		t.Fatalf("frame failed to cross the secured line: %v", err)
	}

	select {
	case got := <-frameDone:
		if got.RequestID != request.RequestID || got.Operation != targetaccess.OpCapabilities {
			t.Fatalf("frame that crossed the wire was not the one we sent: %#v", got)
		}
		t.Logf("wire round-trip OK: request %q over real mTLS line, rc=0", got.RequestID)
	case <-time.After(time.Second):
		t.Fatal("server never received the frame that should have crossed the secured line")
	}
}
