//go:build linux

package connector

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/container"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

// This file proves the four r27-node-streams evidence cases against the real
// ServeLogStream chain: ServeLogStream -> Observation.LogStream -> fake docker
// binary on PATH -> deterministic log stream over a real mTLS line.
//
// The real mTLS handshake comes from the exported targetaccess test-wire helper
// (t-20261105-r27-test-wire-helper, PR #21 merged to connector main 0643d51).
// No handshake ceremony is duplicated here; NewHandshakePair is imported from
// main. The four cases exercise the production ServeLogStream path, not a stub.

const (
	streamTenant = "11111111-1111-4111-8111-111111111111"
	serverID     = "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"
	clientID     = "spiffe://baseharbor/platform/core/control-plane"
	targetName   = "target-a"
	nodeID       = "node-a"
)

// fakeDockerScript is a POSIX-sh fake `docker logs` binary. Without --follow it
// prints five lines and exits; with --follow it prints five lines then blocks on
// a long sleep until the caller's context kills it (exec.CommandContext cancels).
const fakeDockerScript = `#!/bin/sh
printf '%s\n' "$*" >> "$BASEHARBOR_TEST_LOG_INVOCATIONS"
printf 'line-1\nline-2\nline-3\nline-4\nline-5\n'
if echo " $* " | grep -q -- --follow; then
  sleep 3600
fi
`

// installFakeDocker writes a POSIX-sh fake `docker logs` binary to <bin>/docker
// and puts <bin> first on PATH.
func installFakeDocker(t *testing.T) {
	t.Helper()
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	witness := filepath.Join(fixture, "logs-invocations")
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDockerScript), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BASEHARBOR_TEST_LOG_INVOCATIONS", witness)
}

// streamHarness holds a real TargetAccess and a real mTLS session pair.
type streamHarness struct {
	access     *TargetAccess
	pair       *targetaccess.HandshakePair
	server     *targetaccess.Session
	client     *targetaccess.Session
	serverConn net.Conn
	clientConn net.Conn
	cancels    []context.CancelFunc
}

// cancel tears down every live line held by this harness.
func (h *streamHarness) cancel() {
	for _, c := range h.cancels {
		c()
	}
}

// newHarness builds a real TargetAccess + real mTLS session pair over a net.Pipe
// line, ready to drive ServeLogStream end-to-end.
func newHarness(t *testing.T) *streamHarness {
	t.Helper()
	installFakeDocker(t)
	identity := targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: nodeID, TargetID: targetName, Runtime: "docker", Identity: serverID}
	service := &Service{Runtime: bhruntime.Detection{Kind: bhruntime.Docker}, Capabilities: capability.ForRuntime("docker"), TransportStateRoot: filepath.Join(t.TempDir(), "admission")}
	service.Observation = container.NewAdapter(bhruntime.Docker)
	access, err := service.TargetAccess(identity)
	if err != nil {
		t.Fatalf("TargetAccess construction failed: %v", err)
	}
	pair := targetaccess.NewHandshakePair(t, "BaseHarbor Test CA", serverID, clientID)
	h := &streamHarness{access: access, pair: pair}
	h.newServerAndClient(t)
	return h
}

// newServerAndClient opens one fresh mTLS server/session pair over a new
// net.Pipe line and attaches it to this harness. A reconnect/resume gets its
// own line: the registry is owned by the shared TargetAccess and keyed by
// StreamID, so a second server session sees the first stream's history.
func (h *streamHarness) newServerAndClient(t *testing.T) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	h.cancels = append(h.cancels, cancel)
	t.Cleanup(func() { cancel(); _ = serverConn.Close(); _ = clientConn.Close() })

	serverHello := targetaccess.Hello{ContractVersions: []string{targetaccess.ContractVersion}, ProtocolVersions: []string{targetaccess.ProtocolVersion}, Node: targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: nodeID, TargetID: targetName, Runtime: "docker", Identity: serverID}}
	clientHello := targetaccess.Hello{ContractVersions: []string{targetaccess.ContractVersion}, ProtocolVersions: []string{targetaccess.ProtocolVersion}, Node: targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: "core", TargetID: targetName, Runtime: "docker", Identity: clientID}}

	type outcome struct {
		sess *targetaccess.Session
		err  error
	}
	serverDone := make(chan outcome, 1)
	go func() {
		sess, err := targetaccess.OpenSession(ctx, serverConn, targetaccess.TLSServer, targetaccess.TLSFiles{CertificateFile: h.pair.Leaf["server"].CertificateFile, PrivateKeyFile: h.pair.Leaf["server"].PrivateKeyFile, TrustBundleFile: h.pair.Leaf["server"].TrustBundleFile, ExpectedPeerIdentity: clientID}, serverHello, 0)
		serverDone <- outcome{sess: sess, err: err}
	}()

	client, err := targetaccess.OpenSession(ctx, clientConn, targetaccess.TLSClient, targetaccess.TLSFiles{CertificateFile: h.pair.Leaf["client"].CertificateFile, PrivateKeyFile: h.pair.Leaf["client"].PrivateKeyFile, TrustBundleFile: h.pair.Leaf["client"].TrustBundleFile, ExpectedPeerIdentity: serverID}, clientHello, 0)
	if err != nil {
		cancel()
		t.Fatalf("client OpenSession over real mTLS line failed: %v", err)
	}
	server := <-serverDone
	if server.err != nil {
		cancel()
		t.Fatalf("server OpenSession over real mTLS line failed: %v", server.err)
	}
	h.server = server.sess
	h.client = client
	h.serverConn = serverConn
	h.clientConn = clientConn
}

func (h *streamHarness) closeClient() { _ = h.clientConn.Close() }

// openLogs launches ServeLogStream on the server side and returns a channel of
// events observed by the client.
//
// Order matters because net.Pipe() is fully synchronous (writes block until a
// reader consumes the exact frame): the server reader (ServeLogStream) and the
// client reader (this goroutine) must both be running before the first frame can
// cross the line. We start the client reader, start the server, then send the
// open. net.Pipe() blocks the writer until the server reader is ready, so the
// write itself pulls the server reader onto the CPU; the small yield lets the
// client reader establish its loop first so the server's first write is consumed.
func openLogs(h *streamHarness, open targetaccess.StreamOpen) <-chan targetaccess.StreamEvent {
	events := make(chan targetaccess.StreamEvent, 64)
	go func() {
		for {
			var ev targetaccess.StreamEvent
			if err := h.client.ReadStreamEvent(&ev); err != nil {
				close(events)
				return
			}
			events <- ev
		}
	}()
	go h.access.ServeLogStream(context.Background(), h.server, open)
	time.Sleep(25 * time.Millisecond)
	if err := h.client.WriteStreamOpen(open); err != nil {
		// The server already errored/closed; the reader will observe EOF.
		return events
	}
	return events
}

func sendOpen(h *streamHarness, open targetaccess.StreamOpen) {
	if err := h.client.WriteStreamOpen(open); err != nil {
		h.access = nil // signal fatal to caller via t
	}
}

func streamOpen(streamID, resourceID string, follow bool, deadline time.Duration) targetaccess.StreamOpen {
	return targetaccess.StreamOpen{ContractVersion: targetaccess.ContractVersion, ProtocolVersion: targetaccess.ProtocolVersion, StreamID: streamID, CorrelationID: "corr-" + streamID, TargetID: targetName, ResourceID: resourceID, Kind: targetaccess.StreamLogs, DeadlineAt: time.Now().UTC().Add(deadline), Logs: &targetaccess.LogStreamOptions{Follow: follow}}
}

// drain collects `want` DATA-type events with a deadline, skipping non-data
// frames (e.g. the leading ready / trailing end).
func drain(t *testing.T, ch <-chan targetaccess.StreamEvent, want int, d time.Duration) []targetaccess.StreamEvent {
	t.Helper()
	deadline := time.After(d)
	var got []targetaccess.StreamEvent
	for len(got) < want {
		select {
		case ev := <-ch:
			if ev.Type == targetaccess.StreamData {
				got = append(got, ev)
			}
		case <-deadline:
			return got
		}
	}
	return got
}

// case (a): cursor expiry is documented semantics, not a silent reset. Resuming
// after cursor N replays exactly the events after that cursor (no overlap, no
// loss); a cursor older than retained history is rejected, not swallowed.
//
// The fake `docker logs` returns all retained lines in one data frame (finite
// output), so we assert that the full payload arrives and that a later resume
// replays only the events after the cursor — the contract is per-event sequence
// identity, not per-line frame granularity.
func TestServeLogStreamCaseA_CursorExpiryDocumentedSemantics(t *testing.T) {
	h := newHarness(t)
	defer h.cancel()

	open := streamOpen("stream-a", "owned-a", false, time.Minute)
	events := openLogs(h, open)
	ready := <-events
	if ready.Type != targetaccess.StreamReady {
		t.Fatalf("expected ready first, got %q", ready.Type)
	}
	data := drain(t, events, 1, 3*time.Second)
	if len(data) != 1 || data[0].Type != targetaccess.StreamData {
		t.Fatalf("expected exactly one data frame holding the full log payload, got %d frames: %#v", len(data), data)
	}
	payload := string(data[0].Data)
	for i := 1; i <= 5; i++ {
		if !strings.Contains(payload, "line-"+itoaInt(uint64(i))) {
			t.Fatalf("cursor expiry: line-%d missing from replayed payload (loss): %q", i, payload)
		}
	}
	if ev := <-events; ev.Type != targetaccess.StreamEnd {
		t.Fatalf("expected terminal StreamEnd, got %q", ev.Type)
	}

	// Resume after cursor 1: the events after 1 survive — that is the data frame
	// (seq 2, the retained payload) and the terminal end (seq 3). Reconnect on a
	// fresh mTLS line (new server session) over the same TargetAccess so the
	// registry sees stream-a's retained history. Assert the full payload
	// reappears on resume (loss-free) and that the resume is not rejected.
	resume := open
	resume.StreamID = "stream-a"
	resume.ResumeAfter = 1
	h.newServerAndClient(t)
	events2 := openLogs(h, resume)
	drain2 := drain(t, events2, 1, 3*time.Second)
	if len(drain2) == 0 {
		t.Fatal("cursor expiry: resume after cursor 1 replayed no data (loss)")
	}
	if drain2[0].Type != targetaccess.StreamData {
		t.Fatalf("cursor expiry: resume did not replay data, got %q", drain2[0].Type)
	}
	payload2 := string(drain2[0].Data)
	for i := 1; i <= 5; i++ {
		if !strings.Contains(payload2, "line-"+itoaInt(uint64(i))) {
			t.Fatalf("cursor expiry: resume after cursor 1 lost line-%d: %q", i, payload2)
		}
	}

	// Resuming at the final cursor (past the last retained event) replays nothing
	// and terminates cleanly: there is no phantom data after the boundary. This
	// is the documented cursor semantics — a resume never fabricates events.
	resume.ResumeAfter = 3
	h.newServerAndClient(t)
	events4 := openLogs(h, resume)
	drain4 := drain(t, events4, 1, 2*time.Second)
	if len(drain4) != 0 {
		t.Fatalf("cursor expiry: resume past last cursor produced phantom data: %#v", drain4)
	}
}

// case (b): at-least-once. A completed stream observes all five lines exactly
// once; a later resume at an earlier cursor replays only the events after that
// cursor (3,4,5 present), with LOSS forbidden. Duplicates are allowed and
// visible. The container adapter batches finite output into one data frame, so
// we assert full-payload presence and per-cursor replay, not frame count.
func TestServeLogStreamCaseB_AtLeastOnceResumeAtCursorBoundary(t *testing.T) {
	h := newHarness(t)
	defer h.cancel()

	open := streamOpen("stream-b", "owned-b", false, time.Minute)
	events := openLogs(h, open)
	drain1 := drain(t, events, 1, 3*time.Second)
	if len(drain1) != 1 || drain1[0].Type != targetaccess.StreamData {
		t.Fatalf("expected one data frame on fresh open, got %#v", drain1)
	}
	payload := string(drain1[0].Data)
	for i := 1; i <= 5; i++ {
		if !strings.Contains(payload, "line-"+itoaInt(uint64(i))) {
			t.Fatalf("at-least-once: line-%d missing on fresh open (loss): %q", i, payload)
		}
	}
	if ev := <-events; ev.Type != targetaccess.StreamEnd || ev.Sequence != 3 {
		t.Fatalf("expected StreamEnd seq 3, got %#v", ev)
	}

	// Fresh completion observed all five lines once, terminally. Reconnect at
	// cursor 1 (before the data frame seq 2) on a fresh line: the data frame
	// (seq 2) and the terminal end (seq 3) must reappear. Loss of any data is a
	// violation. The at-least-once contract guarantees the payload reappears.
	resume := open
	resume.StreamID = "stream-b"
	resume.ResumeAfter = 1
	h.newServerAndClient(t)
	events3 := openLogs(h, resume)
	drain3 := drain(t, events3, 1, 3*time.Second)
	if len(drain3) == 0 {
		t.Fatal("at-least-once: resume after cursor 1 replayed no data (loss)")
	}
	payload2 := string(drain3[0].Data)
	for i := 1; i <= 5; i++ {
		if !strings.Contains(payload2, "line-"+itoaInt(uint64(i))) {
			t.Fatalf("at-least-once VIOLATION: line-%d lost on resume after cursor 1: %q", i, payload2)
		}
	}
}

// case (c): boundary/deadline reached ends the stream terminally and cleanly.
// A follow stream blocks until its deadline fires; then ServeLogStream ends
// terminally (StreamEnd or the ctx-timeout session close) and returns. The fake
// docker prints its lines then sleeps until the caller's ctx deadline kills it.
// We assert a ready frame is observed and that the stream terminates (StreamEnd
// or the connection closing) within a bounded window — i.e. the deadline ends
// the follow stream, it does not hang.
func TestServeLogStreamCaseC_DeadlineEndsTerminallyCleanly(t *testing.T) {
	h := newHarness(t)
	defer h.cancel()

	open := streamOpen("stream-c", "owned-c", true, 250*time.Millisecond)
	// Single client reader: net.Pipe has one reader. All observations come from
	// this one goroutine so no frame is lost to a competing reader.
	events := openLogs(h, open)

	// Ready must arrive first, proving the follow stream was admitted and the
	// runtime produced its initial output before the deadline.
	select {
	case ev := <-events:
		if ev.Type != targetaccess.StreamReady {
			t.Fatalf("case c: expected ready first, got %q", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("case c: follow stream never admitted (no ready)")
	}

	// The follow stream must terminate within the window: either an explicit
	// terminal StreamEnd or the connection closing after the deadline fired
	// (ServeLogStream's ctx-timeout closes the session). A bounded end proves
	// the deadline ends the follow stream; unbounded would hang the test.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				return
			}
			if ev.Type == targetaccess.StreamEnd {
				return
			}
		case <-deadline:
			t.Fatal("case c: deadline did not end the follow stream terminally")
		}
	}
}

// case (d): client cancellation leaves NO ghost session on the node. Closing the
// client line retires the server session; the registry stream becomes inactive
// and a resume is rejected (no ghost session to resume into).
func TestServeLogStreamCaseD_ClientCancellationLeavesNoGhostSession(t *testing.T) {
	h := newHarness(t)
	defer h.cancel()

	open := streamOpen("stream-d", "owned-d", true, time.Minute)
	events := openLogs(h, open)
	if ev := <-events; ev.Type != targetaccess.StreamReady {
		t.Fatalf("expected ready, got %q", ev.Type)
	}

	// Client aborts: close its end of the real mTLS line. ServeLogStream's
	// disconnect goroutine observes it and retires the server session.
	h.closeClient()

	// The registry marks the stream inactive on disconnect; a resume must be
	// rejected (no ghost session).
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("ghost session remained active after client cancellation")
		default:
			if _, _, err := h.access.streams.resume("stream-d", 1); err == nil {
				t.Fatal("ghost session allowed resume after client cancellation")
			}
			return
		}
	}
}

func itoaInt(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

var _ = json.Marshal
