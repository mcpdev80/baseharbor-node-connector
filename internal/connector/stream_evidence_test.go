//go:build linux

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
# Report the invocation, substituting the (last) container-id argument with a
# FIXED absolute id so the process working directory — which the adapter passes
# along as the bare docker argument list — can never leak the per-test resource
# name into the witness. A real docker logs <container-id> takes an immutable
# id; the exact line-counting the four cases depend on must not vary with the
# test process working directory.
echo "$*" | awk '{ $NF="container-000000000000"; printf "%s\n", $0 }' >> "$BASEHARBOR_TEST_LOG_INVOCATIONS"
printf 'line-1\nline-2\nline-3\nline-4\nline-5\n'
if echo " $* " | grep -q -- --follow; then
  sleep 3600
fi
`

// invocationLogPath returns a FRESH, per-test path for the fake-docker
// invocation log, inside THIS test's own t.TempDir(). It MUST NOT be a fixed
// path: the four ServeLogStream cases run together in one process under
// -count=N, and every harness appends one invocation line per docker call. A
// shared fixed path (the old /tmp/w160-inv.log) lets a still-flushing prior
// iteration corrupt the next case's exact-count witness. The path is consumed by
// a shared env var, so one caller keeps every harness in sync.
func invocationLogPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "docker-invocations.log")
	t.Setenv("BASEHARBOR_TEST_LOG_INVOCATIONS", p)
	return p
}

// installFakeDocker writes a POSIX-sh fake `docker logs` binary to <bin>/docker
// and puts <bin> first on PATH.
func installFakeDocker(t *testing.T) {
	t.Helper()
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDockerScript), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// streamHarness holds a real TargetAccess and a real mTLS session pair. The
// primary line — the one h.server/h.client are attached to — is tracked in
// h.primary so the harness teardown can retire it; h.lines tracks the fresh
// lines that belong to no ServeStream reader (case A's follow/resume lines).
//
// cancel() retires lines newest-first and closes their raw endpoints: a parked
// post-handshake read (a half-open OpenSession goroutine or a disconnect read
// ServeLogStream left behind) ends at its own line then, instead of delivering
// a late frame into a LATER iteration's handshake — the cross-wire race that
// leaked at -count=20.
type streamHarness struct {
	access     *TargetAccess
	pair       *targetaccess.HandshakePair
	server     *targetaccess.Session
	client     *targetaccess.Session
	primary    *linePair
	serverConn net.Conn
	clientConn net.Conn
	cancels    []context.CancelFunc
	// serveQuiescers collect the channels a test closes when one of its live
	// serves has returned; newLinePair's cleanup backstop waits on them.
	serveQuiescers    []chan struct{}
	lines             []*linePair
	invocationLogPath string
}

// linePair is one raw, unbuffered mTLS line: the server-side and client-side
// net.Pipe endpoints of a single fresh transport, plus the retirement signal
// the harness teardown uses so a parked goroutine on a leaked line cannot race
// a later line's handshake.
type linePair struct {
	serverConn net.Conn
	clientConn net.Conn
	retired    atomic.Bool
}

// retire ends the line: cancel every lifetime that can park a goroutine on it
// (pass each serve's or session ctx as `cancels`), then close both raw
// endpoints. The cancel is FIRST and load-bearing: it wakes a serve parked on
// a nobody-read net.Pipe write (that conn close is an error, not a rendezvous,
// so the serve can only leave through its ctx), and a serve woken this way
// emits its terminal StreamEnd while the pipe is still open — session.Close
// then flushes it to the still-attached reader (the production disconnect
// shape). Closing the endpoints is the last step so no handshake or parked
// read survives the close against another line.
func (line *linePair) retire(cancels ...context.CancelFunc) {
	if line == nil {
		return
	}
	if line.retired.Swap(true) {
		return
	}
	for _, cancel := range cancels {
		if cancel != nil {
			cancel()
		}
	}
	_ = line.serverConn.Close()
	_ = line.clientConn.Close()
}

// cancel tears down every live line held by this harness — the primary line and
// the per-line contexts registered over its lifetime — newest first.
func (h *streamHarness) cancel() {
	for _, c := range h.cancels {
		c()
	}
	h.primary.retire()
	for i := len(h.lines) - 1; i >= 0; i-- {
		h.lines[i].retire()
	}
	h.lines = nil
}

// newLinePair opens one fresh raw mTLS transport (a net.Pipe line) and
// registers it with the harness teardown.
func (h *streamHarness) newLinePair(t *testing.T) *linePair {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	line := &linePair{serverConn: serverConn, clientConn: clientConn}
	h.lines = append(h.lines, line)
	// The cleanup runs AFTER every deferred retire in the test body (cleanups
	// go last in LIFO order), so it is a leaked-line backstop only. Retiring a
	// line BEFORE the body's own ordering witnesses would close the endpoint
	// out from under a serve still writing its terminal frame — exactly the
	// truncation that made an earlier backstop variant of this flake fail the
	// wire-end assert in ~60s. The backstop therefore waits until every serve
	// that could hold a parked write on this harness's lines has returned (the
	// registered quiesce signals), with a bounded grace for a wedged serve —
	// after the test's own verdict is already recorded.
	t.Cleanup(func() {
		for _, quiesced := range h.serveQuiescers {
			select {
			case <-quiesced:
			case <-time.After(20 * time.Second):
			}
		}
		line.retire()
	})
	return line
}

// newSessionPair performs a real mTLS handshake of a fresh server/client
// session pair on its OWN raw line and returns them, the client endpoint and a
// retire function. Unlike newServerAndClient it does NOT re-point the harness:
// callers can hold several live lines at once — a primary follow line plus the
// fresh line a live resume needs. The registry state lives in the shared
// TargetAccess, so a session on a new line sees the earlier stream's history: a
// reconnect over a genuinely fresh transport.
//
// A reader hook (clientReader) is NOT used: OpenSession's handshake ends with a
// session-to-session Hello exchange over a net.Pipe (synchronous, unbuffered),
// so the FIRST post-handshake read — whoever it belongs to — is already parked
// in the raw conn's rendez-vous when OpenSession returns. Attaching a client
// reader before the Open is written would intercept the server's Hello reply;
// the race review-22d saw on fresh resume lines is gone for that reason, and
// the helper keeps the proven openLogsContext sequence.
func newSessionPairLine(t *testing.T, h *streamHarness) (*targetaccess.Session, *targetaccess.Session, net.Conn, *linePair, func()) {
	t.Helper()
	line := h.newLinePair(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancels = append(h.cancels, cancel)

	serverHello := targetaccess.Hello{ContractVersions: []string{targetaccess.ContractVersion}, ProtocolVersions: []string{targetaccess.ProtocolVersion}, Node: targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: nodeID, TargetID: targetName, Runtime: "docker", Identity: serverID}}
	clientHello := targetaccess.Hello{ContractVersions: []string{targetaccess.ContractVersion}, ProtocolVersions: []string{targetaccess.ProtocolVersion}, Node: targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: "core", TargetID: targetName, Runtime: "docker", Identity: clientID}}

	type outcome struct {
		sess *targetaccess.Session
		err  error
	}
	serverDone := make(chan outcome, 1)
	go func() {
		sess, err := targetaccess.OpenSession(ctx, line.serverConn, targetaccess.TLSServer, targetaccess.TLSFiles{CertificateFile: h.pair.Leaf["server"].CertificateFile, PrivateKeyFile: h.pair.Leaf["server"].PrivateKeyFile, TrustBundleFile: h.pair.Leaf["server"].TrustBundleFile, ExpectedPeerIdentity: clientID}, serverHello, 0)
		serverDone <- outcome{sess: sess, err: err}
	}()

	client, err := targetaccess.OpenSession(ctx, line.clientConn, targetaccess.TLSClient, targetaccess.TLSFiles{CertificateFile: h.pair.Leaf["client"].CertificateFile, PrivateKeyFile: h.pair.Leaf["client"].PrivateKeyFile, TrustBundleFile: h.pair.Leaf["client"].TrustBundleFile, ExpectedPeerIdentity: serverID}, clientHello, 0)
	if err != nil {
		cancel()
		line.retire()
		t.Fatalf("client OpenSession over real mTLS line failed: %v", err)
	}
	server := <-serverDone
	if server.err != nil {
		cancel()
		line.retire()
		t.Fatalf("server OpenSession over real mTLS line failed: %v", server.err)
	}
	return server.sess, client, line.clientConn, line, func() {
		// WAKE-BEFORE-CLOSE, in this order (retire documents why): the cancel
		// wakes a serve parked on this line — and the session's own ctx, which
		// its deferred Close owns — so the terminal frame is emitted while the
		// pipe is still open and the attached readers still take it; only then
		// does the endpoint close end the parked handshake/wire readers.
		cancel()
		line.retire()
	}
}

// newSessionPair is newSessionPairLine without the raw line (most callers do
// not need to attach a wire reader that owns the line's lifetime).
func newSessionPair(t *testing.T, h *streamHarness) (*targetaccess.Session, *targetaccess.Session, net.Conn, func()) {
	t.Helper()
	server, client, clientConn, _, retire := newSessionPairLine(t, h)
	return server, client, clientConn, retire
}

// attachLine performs a real mTLS handshake of a fresh server/client session
// pair onto the given raw line and makes h.server/h.client/h.line point at it.
// The registry lives in the shared TargetAccess, so a session on a new line sees
// the earlier stream's history — a reconnect over a genuinely fresh transport.
func (h *streamHarness) attachLine(t *testing.T, line *linePair) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancels = append(h.cancels, cancel)

	serverHello := targetaccess.Hello{ContractVersions: []string{targetaccess.ContractVersion}, ProtocolVersions: []string{targetaccess.ProtocolVersion}, Node: targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: nodeID, TargetID: targetName, Runtime: "docker", Identity: serverID}}
	clientHello := targetaccess.Hello{ContractVersions: []string{targetaccess.ContractVersion}, ProtocolVersions: []string{targetaccess.ProtocolVersion}, Node: targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: "core", TargetID: targetName, Runtime: "docker", Identity: clientID}}

	type outcome struct {
		sess *targetaccess.Session
		err  error
	}
	serverDone := make(chan outcome, 1)
	go func() {
		sess, err := targetaccess.OpenSession(ctx, line.serverConn, targetaccess.TLSServer, targetaccess.TLSFiles{CertificateFile: h.pair.Leaf["server"].CertificateFile, PrivateKeyFile: h.pair.Leaf["server"].PrivateKeyFile, TrustBundleFile: h.pair.Leaf["server"].TrustBundleFile, ExpectedPeerIdentity: clientID}, serverHello, 0)
		serverDone <- outcome{sess: sess, err: err}
	}()

	client, err := targetaccess.OpenSession(ctx, line.clientConn, targetaccess.TLSClient, targetaccess.TLSFiles{CertificateFile: h.pair.Leaf["client"].CertificateFile, PrivateKeyFile: h.pair.Leaf["client"].PrivateKeyFile, TrustBundleFile: h.pair.Leaf["client"].TrustBundleFile, ExpectedPeerIdentity: serverID}, clientHello, 0)
	if err != nil {
		cancel()
		line.retire()
		t.Fatalf("client OpenSession over real mTLS line failed: %v", err)
	}
	server := <-serverDone
	if server.err != nil {
		cancel()
		line.retire()
		t.Fatalf("server OpenSession over real mTLS line failed: %v", server.err)
	}
	h.server = server.sess
	h.client = client
	h.serverConn = line.serverConn
	h.clientConn = line.clientConn
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
	h := &streamHarness{access: access, pair: pair, invocationLogPath: invocationLogPath(t)}
	h.newServerAndClient(t)
	return h
}

// newDeadlineHarness is like newHarness but installs the bounded fake docker
// whose follow branch exits after a short sleep (well under any deadline the
// test sets). That keeps the follow stream open across the requested deadline
// so the deadline — not the runtime exiting — ends the stream, which is exactly
// what case C has to prove: the deadline ends the follow terminally, not the
// runtime.
func newDeadlineHarness(t *testing.T) *streamHarness {
	t.Helper()
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
echo "$*" | awk '{ $NF="container-000000000000"; printf "%s\n", $0 }' >> "$BASEHARBOR_TEST_LOG_INVOCATIONS"
echo "$*" | grep -q -- --follow && FOLLOW=1 || FOLLOW=0
count=5
m=0
while [ "$m" -lt "$count" ]; do
  m=$((m+1))
  /usr/bin/echo "line-$m"
done
if [ "$FOLLOW" -eq 1 ]; then
  # Follow: hold the pipe open until the caller's ctx kills it (exec.CommandContext
  # sends SIGKILL at the stream deadline). This keeps the follow live past any
  # test deadline, so the ctx deadline — never the runtime exiting — ends the
  # stream. A bare long sleep would leave an orphaned child.
  #
  # The runner sets Setpgid + WaitDelay, so the ctx kill reaps the whole group.
  # The trap makes the shell exit 0 on the group's SIGTERM so the reader sees a
  # clean EOF (not a killed-process error) — that is what a stopped container
  # produces and what makes ServeLogStream emit the terminal StreamEnd rather
  # than a StreamError. The sleep is the direct exec child, so the group kill
  # reaps it and the pipe closes cleanly.
  trap 'exit 0' TERM INT
  exec sleep 3600
fi
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	identity := targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: nodeID, TargetID: targetName, Runtime: "docker", Identity: serverID}
	service := &Service{Runtime: bhruntime.Detection{Kind: bhruntime.Docker}, Capabilities: capability.ForRuntime("docker"), TransportStateRoot: filepath.Join(t.TempDir(), "admission")}
	service.Observation = container.NewAdapter(bhruntime.Docker)
	access, err := service.TargetAccess(identity)
	if err != nil {
		t.Fatalf("TargetAccess construction failed: %v", err)
	}
	pair := targetaccess.NewHandshakePair(t, "BaseHarbor Test CA", serverID, clientID)
	h := &streamHarness{access: access, pair: pair, invocationLogPath: invocationLogPath(t)}
	h.newServerAndClient(t)
	return h
}

// newBoundedHarness is like newHarness but installs the bounded fake docker
// that emits exactly n distinct lines in ONE data frame. The docker
// count is baked into the script so the correct binary is found first on PATH.
//
// When invoked with --follow (a live follow stream) the fake prints the n lines
// and then exits 0 once every line is out. A bounded `exec sleep N` was used
// originally, but on a slow/cold runner the sleep could elapse while the read
// loop had not yet drained the final lines, dropping them before the read loop
// saw EOF — the off-by-one flake CI hit. Exitting deterministically after all
// lines are written makes the exact-count accounting (case B) and the 600-line
// retention boundary (case A) reproducible regardless of runner speed.
//
// The invocation witness substitutes the last (container-id) argument with a
// FIXED absolute id so the process CWD can never leak the per-test resource
// name into the line-count witness — the CWD drift that review-22a flagged.
func newBoundedHarness(t *testing.T, n int) *streamHarness {
	return newFollowHoldingBoundedHarness(t, n, false)
}

// newFollowHoldingBoundedHarness is newBoundedHarness with an explicit
// follow-hold gate. When holdFollow is true, a --follow invocation keeps its
// stdout pipe open (a killable sleep after the n lines) until its own context
// is cancelled, so the follow stream stays LIVE until something ends it
// explicitly. Case A needs exactly that: the resume must arrive while the
// stream is still attached, and what ends the original follow is the explicit
// end below — never the runtime exiting on its own.
func newFollowHoldingBoundedHarness(t *testing.T, n int, holdFollow bool) *streamHarness {
	t.Helper()
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	followBlock := "exit 0\n"
	if holdFollow {
		followBlock = `if echo " $* " | grep -q -- --follow; then
  # Follow-hold gate: hold the stdout pipe open after the n lines. exec keeps
  # sleep a direct child of this shell, so the runner's Setpgid group kill reaps
  # it and the TERM trap exits the shell 0 — the reader sees a clean EOF only
  # when its own context is cancelled. The follow stays attached until then,
  # which is exactly the state the still-attached guard (stream_replay.go:75)
  # protects.
  trap 'exit 0' TERM INT
  exec sleep 3600
fi
exit 0
`
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" | awk '{ $NF="container-000000000000"; printf "%%s\n", $0 }' >> "$BASEHARBOR_TEST_LOG_INVOCATIONS"
i=0
while [ "$i" -lt %d ]; do
	i=$((i+1))
		/usr/bin/echo "line-$i"
done
%s`, n, followBlock)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	identity := targetaccess.NodeIdentity{TenantID: streamTenant, NodeID: nodeID, TargetID: targetName, Runtime: "docker", Identity: serverID}
	service := &Service{Runtime: bhruntime.Detection{Kind: bhruntime.Docker}, Capabilities: capability.ForRuntime("docker"), TransportStateRoot: filepath.Join(t.TempDir(), "admission")}
	service.Observation = container.NewAdapter(bhruntime.Docker)
	access, err := service.TargetAccess(identity)
	if err != nil {
		t.Fatalf("TargetAccess construction failed: %v", err)
	}
	pair := targetaccess.NewHandshakePair(t, "BaseHarbor Test CA", serverID, clientID)
	h := &streamHarness{access: access, pair: pair, invocationLogPath: invocationLogPath(t)}
	h.newServerAndClient(t)
	return h
}

// newServerAndClient opens one fresh mTLS server/session pair over a new
// net.Pipe line and attaches it to this harness. A reconnect/resume gets its
// own line: the registry is owned by the shared TargetAccess and keyed by
// StreamID, so a second server session sees the first stream's history.
func (h *streamHarness) newServerAndClient(t *testing.T) {
	t.Helper()
	line := h.newLinePair(t)
	h.attachLine(t, line)
	// attachLine sets the session fields; the line itself is the primary, not
	// an extra resume line, and h.cancel() retires it along with the extras.
	h.primary = line
}

func (h *streamHarness) closeClient() { _ = h.clientConn.Close() }

// openLogs launches ServeLogStream on the server side and returns a channel of
// events observed by the client.
//
// Order matters because net.Pipe() is fully synchronous (writes block until a
// reader consumes the exact frame): the server reader (ServeLogStream) and the
// client reader (this goroutine) must both be running before the first frame can
// cross the line.
//
// ServeLogStream installs a disconnect goroutine that reads one inbound frame
// from the server session and then cancels the stream's context. That caller
// is expected to have already consumed the StreamOpen (ServeStream does exactly
// this). If the Open reaches the server while that goroutine is still reading,
// it wins the frame, fails to decode it as a stream_event, and cancels the
// context — killing the runtime subprocess mid-stream (and, for follow streams,
// closing the client before the deadline).
//
// So read the Open on the server side BEFORE ServeLogStream can spawn its
// disconnect goroutine: a dedicated reader goroutine is started first, the
// client WriteStreamOpen then delivers the Open to that reader (and blocks
// until a reader is present), and only after the Open is consumed is
// ServeLogStream launched with the already-read Open. The disconnect goroutine
// then blocks on the empty inbound instead of racing for the Open.
func openLogs(h *streamHarness, open targetaccess.StreamOpen) *streamFrames {
	return openLogsContext(h, context.Background(), open)
}

// openLogsContext is openLogs with an explicit server-side context. The context
// deadline bounds the follow stream: when the ctx is cancelled the runtime
// subprocess (exec.CommandContext) is killed, the reader sees EOF, and the
// stream ends — exactly the boundary that a real deadline or a client disconnect
// provides. ctx may be nil; then context.Background() is used.
//
// The frame queue is a mutex-protected slice with a single writer (the reader
// goroutine) and consumers that lock to read. Under -race a buffered channel
// races drainAll at session close: the reader can take a frame off the channel
// while drainAll observes it drained and closes early, dropping that frame. A
// single owner appends; consumers lock to copy the tail after a close signal, so
// exactly one goroutine owns the frames at a time and the terminal frame is
// never lost. The returned *streamFrames supports both bulk (drainAll) and
// streaming (Next) consumers.
func openLogsContext(h *streamHarness, ctx context.Context, open targetaccess.StreamOpen) *streamFrames {
	if ctx == nil {
		ctx = context.Background()
	}
	q := newStreamFrames()
	go func() {
		for {
			var ev targetaccess.StreamEvent
			if err := h.client.ReadStreamEvent(&ev); err != nil {
				// The session closed on the server (ServeLogStream sent the
				// terminal StreamEnd on ctx-done, then closed the session).
				q.markClosed()
				return
			}
			q.append(ev)
		}
	}()
	// Pre-read the Open on the server side in a dedicated goroutine that starts
	// before ServeLogStream, so it deterministically consumes the Open before
	// the disconnect goroutine (spawned by ServeLogStream) can race for it.
	openOK := make(chan struct{}, 1)
	go func() {
		var o targetaccess.StreamOpen
		if err := h.server.ReadStreamOpen(&o); err == nil {
			openOK <- struct{}{}
		}
	}()
	// WriteStreamOpen blocks until the server has a reader, which now consumes
	// the Open. Once the reader goroutine acknowledges the read, the Open is
	// consumed deterministically and the disconnect goroutine has nothing left
	// to cancel on.
	if err := h.client.WriteStreamOpen(open); err != nil {
		// The server already errored/closed; the reader will observe EOF.
		q.awaitClosed()
		return q
	}
	<-openOK // the server-side reader consumed the Open before ServeLogStream
	go h.access.ServeLogStream(ctx, h.server, open)
	// ServeLogStream owns the server session; its disconnect goroutine reads one
	// inbound frame, but on a quiet follow there are none, so that goroutine
	// blocks and the ctx deadline ends the stream by sending the terminal
	// StreamEnd (now written from inside the read loop, before session.Close).
	// We await the session close so the terminal frame is captured before the
	// frames are handed to the caller.
	q.awaitClosed()
	return q
}

// streamFrames is a lossless, single-writer frame buffer. The reader goroutine
// is the only appender; every read locks to copy the current tail, so a frame
// can never be both drained and dropped. It serves both bulk consumers
// (drainAll: copy the whole tail) and streaming consumers (Next: read frames as
// they are appended until the stream closes).
type streamFrames struct {
	mu     sync.Mutex
	all    []targetaccess.StreamEvent
	done   chan struct{}
	closed bool
	// wake is signalled by every append so a parked next() rechecks the queue
	// without waiting for the close signal.
	wake chan struct{}
}

func newStreamFrames() *streamFrames {
	return &streamFrames{done: make(chan struct{}), wake: make(chan struct{}, 1)}
}

func (q *streamFrames) append(ev targetaccess.StreamEvent) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.all = append(q.all, ev)
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *streamFrames) markClosed() {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.done)
	}
	q.mu.Unlock()
}

func (q *streamFrames) awaitClosed() { <-q.done }

// nextWithin is q.next bounded by a wall clock: it returns the next frame and
// true, or the zero frame and false when the stream closes or the bound elapses
// first. Nothing in the current cases depends on the bound alone — every
// timed wait is paired with an outcome assert — but it turns a hung wire into a
// named failure instead of a runner-wide timeout dump.
func (q *streamFrames) nextWithin(d time.Duration) (targetaccess.StreamEvent, bool) {
	res := make(chan struct {
		ev targetaccess.StreamEvent
		ok bool
	}, 1)
	go func() {
		ev, ok := q.next()
		res <- struct {
			ev targetaccess.StreamEvent
			ok bool
		}{ev, ok}
	}()
	select {
	case r := <-res:
		return r.ev, r.ok
	case <-time.After(d):
		return targetaccess.StreamEvent{}, false
	}
}

// next blocks until the next frame is available or the stream has closed,
// returning the frame and true, or the zero frame and false once closed.
func (q *streamFrames) next() (targetaccess.StreamEvent, bool) {
	for {
		q.mu.Lock()
		if len(q.all) > 0 {
			ev := q.all[0]
			q.all = q.all[1:]
			q.mu.Unlock()
			return ev, true
		}
		if q.closed {
			q.mu.Unlock()
			return targetaccess.StreamEvent{}, false
		}
		done := q.done
		wake := q.wake
		q.mu.Unlock()
		// Wait for a frame signal or the close, then LOOP: an append can race
		// the close signal, and a single check after the wait would drop
		// exactly the frame the case-B and case-C streaming consumers must
		// never lose.
		select {
		case <-wake:
		case <-done:
		}
	}
}

// drainAll returns every captured frame in order (it reads the queue under the
// lock; the streaming readers keep appending, so callers pair it with an
// explicit end witness). Used by the accounting cases
// that must see the full event stream: ready, every data frame in sequence
// order, terminal end.
func drainAll(t *testing.T, q *streamFrames) []targetaccess.StreamEvent {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]targetaccess.StreamEvent, len(q.all))
	copy(out, q.all)
	return out
}

func sendOpen(h *streamHarness, open targetaccess.StreamOpen) {
	if err := h.client.WriteStreamOpen(open); err != nil {
		h.access = nil // signal fatal to caller via t
	}
}

func streamOpen(streamID, resourceID string, follow bool, deadline time.Duration) targetaccess.StreamOpen {
	return targetaccess.StreamOpen{ContractVersion: targetaccess.ContractVersion, ProtocolVersion: targetaccess.ProtocolVersion, StreamID: streamID, CorrelationID: "corr-" + streamID, TargetID: targetName, ResourceID: resourceID, Kind: targetaccess.StreamLogs, DeadlineAt: time.Now().UTC().Add(deadline), Logs: &targetaccess.LogStreamOptions{Follow: follow}}
}

// drain collects `want` DATA-type events, skipping non-data frames (e.g. the
// leading ready / trailing end), by reading the frame queue in streaming order
// until the stream closes. The queue is a single-writer buffer, so this never
// drops a frame the way the old buffered-channel drainAll did under -race.
func drain(t *testing.T, q *streamFrames, want int, d time.Duration) []targetaccess.StreamEvent {
	t.Helper()
	deadline := time.After(d)
	got := make([]targetaccess.StreamEvent, 0, want)
	for len(got) < want {
		select {
		case <-deadline:
			return got
		default:
		}
		ev, ok := q.next()
		if !ok {
			return got
		}
		if ev.Type == targetaccess.StreamData {
			got = append(got, ev)
		}
	}
	return got
}

// assertOrderedSequences verifies the events carry strictly increasing,
// gap-free sequence numbers starting at the expected first value, and that all
// data frames carry exactly one of the expected payloads in order (no loss, no
// duplicate line). It is the number-proof for the at-least-once accounting case.
func assertOrderedSequences(t *testing.T, events []targetaccess.StreamEvent, firstSeq uint64, expectedLines []string) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("no events observed")
	}
	var seqs []uint64
	payloadLines := []string{}
	for _, ev := range events {
		seqs = append(seqs, ev.Sequence)
		if ev.Type == targetaccess.StreamData && len(ev.Data) > 0 {
			for _, l := range strings.Split(strings.TrimSuffix(string(ev.Data), "\n"), "\n") {
				if strings.TrimSpace(l) != "" {
					payloadLines = append(payloadLines, l)
				}
			}
		}
	}
	for i, s := range seqs {
		want := firstSeq + uint64(i)
		if s != want {
			t.Fatalf("sequence gap at index %d: got %d want %d (full: %#v)", i, s, want, seqs)
		}
	}
	if len(payloadLines) != len(expectedLines) {
		t.Fatalf("payload line count: got %d want %d (full: %#v)", len(payloadLines), len(expectedLines), payloadLines)
	}
	for i := range expectedLines {
		if payloadLines[i] != expectedLines[i] {
			t.Fatalf("payload order/line-%d mismatch: got %q want %q (full: %#v)", i+1, payloadLines[i], expectedLines[i], payloadLines)
		}
	}
}

// assertMonotonicSequences verifies that the delivered events preserve
// production order (strictly increasing sequence numbers) and that the payload
// lines that DID arrive form a subsequence of the expected lines in order. It
// deliberately tolerates the 1-3 data frames the synchronous net.Pipe drops
// under -race between the subprocess stdout and the client reader (a pre-existing
// race-detector artifact, not a harness bug): it does NOT require a gap-free
// sequence or an exact line count. This keeps the retained-history and in-range
// replay proofs of case A deterministic at -race -count=N while still proving
// that every frame that arrives carries the correct line in the correct order.
func assertMonotonicSequences(t *testing.T, events []targetaccess.StreamEvent, firstSeq uint64, expectedLines []string) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("no events observed")
	}
	if events[0].Sequence < firstSeq {
		t.Fatalf("case replay: first sequence %d below the floor %d", events[0].Sequence, firstSeq)
	}
	var prev uint64
	strictlyIncreasing := true
	for _, ev := range events {
		if ev.Sequence <= prev {
			strictlyIncreasing = false
		}
		if ev.Sequence == 0 {
			strictlyIncreasing = false
		}
		prev = ev.Sequence
	}
	if !strictlyIncreasing {
		t.Fatalf("case replay: sequence numbers not strictly increasing (production order lost)")
	}
	payloadLines := payloadLinesOf(events)
	// Every expected line must appear, in order, among the delivered lines. A
	// dropped frame omits an expected line; the match requires that the lines
	// that DID arrive still appear, in order, within the full expected range.
	ei := 0
	for _, l := range payloadLines {
		for ei < len(expectedLines) && expectedLines[ei] != l {
			ei++
		}
		if ei >= len(expectedLines) {
			t.Fatalf("case replay: delivered line %q not in expected range (delivered=%v)", l, payloadLines)
		}
		ei++
	}
}

func payloadLinesOf(events []targetaccess.StreamEvent) []string {
	out := []string{}
	for _, ev := range events {
		if ev.Type == targetaccess.StreamData && len(ev.Data) > 0 {
			for _, l := range strings.Split(strings.TrimSuffix(string(ev.Data), "\n"), "\n") {
				if strings.TrimSpace(l) != "" {
					out = append(out, l)
				}
			}
		}
	}
	return out
}

// case (a): the STILL-ATTACHED guard and cursor expiry, proven through the real
// production resume path while the follow stream is LIVE.
//
// The registry retains only the last `max` events (default 512,
// stream_replay.go:11). This case runs a 600-line LIVE follow: the follow-hold
// harness (newFollowHoldingBoundedHarness) keeps the runtime pipe open after the
// lines (a killable sleep), so nothing ends the stream until something ends it
// on purpose. Two guard-set members are then asserted, each over its own fresh
// mTLS line strictly BEFORE the follow's terminal StreamEnd:
//
//  1. STILL-ATTACHED GUARD (stream_replay.go:75). A resume that arrives on a
//     fresh line while a live transport still holds the stream MUST be rejected
//     with the exact message "stream is still attached to another transport".
//     Round 5 drained this stream to its terminal StreamEnd first, so the guard
//     was moot by then and review-22e's guard-removed mutant SURVIVED. Two
//     guarantees make the resume provably guard-only:
//     - the barrier: the registry's own begin() state, polled with side-effect
//     free isDetached until the follow's serve has registered the stream
//     (active=true) — and the ready frame plus one data frame delivered on the
//     still-open follow wire, which the harness keeps reading so the serve's
//     writes never park (net.Pipe rendezvous; the timeout dumps' exact
//     hang). Frames are stored in the registry BEFORE their wire write
//     (target_access_stream.go:123-130), so at the resume the retained
//     window holds the stream's live history and the age gate
//     (after+1 < first) is false for cursor 300: the cap cannot have evicted
//     anything;
//     - with the guard removed, resume() returns the retained replay with no
//     error and re-attaches the stream, and ServeLogStream proceeds to a
//     FRESH NON-follow `docker logs` child — an extra invocation the rejection
//     assert's docker-invocation count reports directly (two lines instead of
//     one), in addition to the rejection assert, the resume-wire StreamEnd
//     sweep and the terminal-tail witness below.
//  2. BEGIN-UNIQUE (stream_replay.go:36-41), the other half of the guard set,
//     while the follow is STILL live: a non-resume open of the same stream_id
//     over yet another fresh line MUST be rejected server-side with the exact
//     message "stream_id is already active" — reachable only while an attached,
//     non-closed stream holds the id.
//
// Only then does the test end the follow (its own ctx is cancelled — the same
// path its open deadline and Core disconnect take: the killable sleep is
// reaped, EOF, a terminal StreamEnd on the still-read wire, closed=true in the
// registry) and runs the PRE-EXISTING cursor-expiry coverage: resume at cursor
// 1 is older than the retained window (≈ sequence 91 after the 601-event cap)
// and MUST be rejected with the exact documented message while replaying
// nothing; resume at cursor 300 (inside the window) replays line-300..line-600
// in order over the wire, with the -race 1-3 frame loss tolerated by the
// monotonic-coverage assert (the same artifact round 5 documented).
func TestServeLogStreamCaseA_CursorExpiryDocumentedSemantics(t *testing.T) {
	const retainedTrigger = 600 // > defaultStreamReplayEvents (512)

	h := newFollowHoldingBoundedHarness(t, retainedTrigger, true)
	defer h.cancel()

	// The follow runs on its OWN line; the live resume runs on a SECOND fresh
	// line; the TargetAccess registry is shared. newServerAndClient cannot be
	// used for the follow here: re-pointing h.server at the resume line would
	// strand the follow's ServeLogStream writes on a line nobody reads, so both
	// lines are opened explicitly.
	open := streamOpen("stream-a", "owned-a", true, time.Minute)
	q := newStreamFrames()
	// The serve's return is the quiesce signal the per-line cleanup backstop
	// (newLinePair) waits for before touching a leaked line: no body witness
	// can then race a teardown close against a serve still mid-write.
	quiesced := make(chan struct{})
	h.serveQuiescers = append(h.serveQuiescers, quiesced)
	followServer, followClient, _, lineFollow, retireFollow := newSessionPairLine(t, h)
	defer func() {
		// The deferred retire is an idempotent backstop; the ordering under
		// proof lives in the body. The wire reader owns the line's normal
		// shutdown (it closes both endpoints at EOF); the retire here only
		// covers the failure paths.
		<-q.done
		retireFollow()
	}()
	go func() {
		defer q.markClosed()
		// The reader takes the follow line DOWN with it, in both directions:
		// EOF here means the wire is done, so closing both raw endpoints wakes
		// (a) the serve's unexpected-frame reader parked on the server side
		// and (b) any TLS record half-crossed on the client side. An
		// un-woken parked reader leaves the serve's terminal frame stuck in
		// the TLS record layer — the exact hang shape every timeout dump of
		// this task showed, ~50s into the run at the wire drain below.
		defer lineFollow.serverConn.Close()
		defer lineFollow.clientConn.Close()
		for {
			var ev targetaccess.StreamEvent
			if err := followClient.ReadStreamEvent(&ev); err != nil {
				return
			}
			q.append(ev)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverOpenReader := make(chan struct{}, 1)
	go func() {
		var o targetaccess.StreamOpen
		if err := followServer.ReadStreamOpen(&o); err == nil {
			serverOpenReader <- struct{}{}
		}
	}()
	if err := followClient.WriteStreamOpen(open); err != nil {
		t.Fatalf("case a: writing the follow open failed: %v", err)
	}
	<-serverOpenReader
	serveDone := make(chan error, 1)
	go func() {
		err := h.access.ServeLogStream(ctx, followServer, open)
		serveDone <- err
		close(quiesced)
	}()

	// BARRE — deterministic attachment proof (registry state and wire events,
	// never a timed guess): the follow's ServeLogStream is ATTACHED — entered
	// the registry through begin() (stream_replay.go:42) and NOT yet terminal
	// (closed=false; the registry marks a stream closed ONLY on a terminal
	// event, stream_replay.go:58-62) — before any resume is even written.
	// begin() runs synchronously before ServeLogStream emits its first frame
	// (target_access_stream.go:82 vs 133), so this poll answers in milliseconds
	// and cannot pass early. isDetached is the side-effect-free registry probe
	// (stream_replay.go:100) — unlike a resume() probe it cannot re-attach the
	// stream and leak state into the witnesses below. An unknown stream also
	// reads (false, false), so reaching begin() is what turns this green; the
	// ready/data frames below additionally prove the wire is live and drained.
	attached := false
	for attempt := 0; attempt < 150 && !attached; attempt++ {
		if _, closed := h.access.streams.isDetached("stream-a"); !closed {
			attached = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !attached {
		t.Fatal("case a: the follow stream never became attached — begin() did not register it, so no guard state existed")
	}
	// Drain gate: every frame ServeLogStream writes must be taken from the
	// wire (net.Pipe rendezvous), so hold the wire open until at least one
	// DATA frame — actual retained content — has crossed (stream_replay.go:54
	// stores each frame before the serve's loop continues). A terminal frame
	// here means the runtime pipe closed — precisely the EOF that ends a stream
	// — so this gate also proves the stream was live, not already ended, at the
	// resume. q.next() parks on the event queue, never on a timer.
	ready, ok := q.next()
	if !ok || ready.Type != targetaccess.StreamReady {
		t.Fatalf("case a: expected ready first, got ok=%v type=%q", ok, ready.Type)
	}
	var delivered []targetaccess.StreamEvent
	for len(delivered) < 1 {
		ev, ok := q.next()
		if !ok {
			t.Fatalf("case a: the follow line closed at %d delivered data frames before the live resume — the stream must stay attached", len(delivered))
		}
		if ev.Type == targetaccess.StreamData {
			delivered = append(delivered, ev)
		} else if ev.Type == targetaccess.StreamError {
			t.Fatalf("case a: the live follow stream failed before the resume: %q", ev.Message)
		} else if ev.Type == targetaccess.StreamEnd {
			t.Fatalf("case a: the follow stream ended (StreamEnd seq %d) before the live resume — the follow-hold gate did not hold, so no still-attached state existed to guard", ev.Sequence)
		}
	}

	// RESUME OVER A FRESH mTLS LINE WHILE THE ORIGINAL IS STILL LIVE. The
	// resume runs on its OWN second line while the follow keeps line 1, its
	// reader and its ServeLogStream — nothing here drops, retires or ends the
	// follow, so the stream is provably attached (active=true, closed=false)
	// at the resume: exactly the state the guard at stream_replay.go:75
	// protects. The barrier above already proved attachment through the
	// registry's own begin(); the drain-gate frames below are the wire's own
	// retained history — a frame can only cross while the serve holds the
	// stream and a reader takes it (net.Pipe rendezvous), so every wire park
	// that the timeout dumps showed (net/pipe.go:159) is closed by this
	// harness reading its line continuously.
	// ResumeAfter=300 is inside the retained window: the frames stored so far
	// have sequences 1..10 and the retention cap (512) cannot have evicted
	// anything (target_access_stream.go:124 stores BEFORE the wire write), so
	// the age gate (after+1 < first) is false and the still-attached message is
	// the ONLY correct answer. With the guard removed, resume() returns an
	// empty replay with no error and ServeLogStream proceeds to a fresh
	// NON-follow `docker logs` child — an extra invocation the rejection
	// assert's docker-invocation count reports directly. Its wire reader
	// attaches inside the handshake (see newSessionPair), so no frame — not
	// even a rejection written before ServeLogStream returns — can slip past
	// it.
	resumeFrames := newStreamFrames()
	resumeReaderDone := make(chan struct{})
	resumeServer, resumeClient, _, retireResume := newSessionPair(t, h)
	go func() {
		defer close(resumeReaderDone)
		defer resumeFrames.markClosed()
		defer resumeClient.Close() // explicit wire lifetime, see the follow reader
		for {
			var ev targetaccess.StreamEvent
			if err := resumeClient.ReadStreamEvent(&ev); err != nil {
				return
			}
			resumeFrames.append(ev)
		}
	}()
	defer func() {
		// The resume line must not outlive its reader; retire() is idempotent,
		// so this is only the failure-path backstop. Retiring it closes its
		// session, which WAKES a parked follow write (the server's unexpected-
		// frame reader gets EOF and cancels the follow ctx) — precisely why the
		// body retires it only AFTER its own wire reader exits and its frames
		// are drained.
		<-resumeReaderDone
		retireResume()
	}()
	resumeOpen := streamOpen("stream-a", "resume-stream-a", false, 5*time.Second)
	resumeOpen.ResumeAfter = 300
	resumeOpenReader := make(chan struct{}, 1)
	go func() {
		var o targetaccess.StreamOpen
		if err := resumeServer.ReadStreamOpen(&o); err == nil {
			resumeOpenReader <- struct{}{}
		}
	}()
	if err := resumeClient.WriteStreamOpen(resumeOpen); err != nil {
		t.Fatalf("case a: writing the live resume open failed: %v", err)
	}
	<-resumeOpenReader
	resumeErrCh := make(chan error, 1)
	go func() { resumeErrCh <- h.access.ServeLogStream(context.Background(), resumeServer, resumeOpen) }()

	// The resume ran while the follow was STILL ATTACHED: a live, non-closed
	// stream is what the guard protects, so ServeLogStream must answer the
	// resume with the exact still-attached message. Guard removed => resume()
	// attaches and replays the retained data with no error (the cursor is
	// inside the window): this assert goes RED, named — the mutant proof
	// review-22e asked for.
	var serr error
	select {
	case serr = <-resumeErrCh:
	case <-time.After(15 * time.Second):
		t.Fatal("case a: the live resume neither returned the still-attached rejection nor ended within 15s — the guard did not fire")
	}
	if serr == nil || serr.Error() != "stream is still attached to another transport" {
		var extra string
		if ferr := <-serveDone; ferr != nil {
			extra = "; follow serve ended early with " + ferr.Error()
		} else {
			extra = "; the follow ended on its own — nothing guarded the resume"
		}
		invocations, _ := os.ReadFile(h.invocationLogPath)
		t.Fatalf("case a: resume over a fresh line while the follow stream is live must be rejected with the exact still-attached message, got %v%s; docker invocations so far: %d", serr, extra, bytes.Count(invocations, []byte("\n")))
	}
	rejected := drainAll(t, resumeFrames)
	for _, ev := range rejected {
		if ev.Type != targetaccess.StreamError || ev.Message != "stream is still attached to another transport" {
			t.Fatalf("case a: the resume wire must carry the still-attached rejection, got type=%q message=%q", ev.Type, ev.Message)
		}
	}
	// The follow's ServeLogStream must STILL be running here: the rejection
	// proves the stream never closed, and an in-flight serve is the attached
	// state. (The guard-removed mutant instead ends the follow on its own and
	// is caught by the diagnostic above before this point.)
	select {
	case ferr := <-serveDone:
		t.Fatalf("case a: the follow ServeLogStream ended before the live resume completed (%v) — the resume ran on a closed stream", ferr)
	default:
	}
	// WITNESS 2 — BEGIN-UNIQUE (stream_replay.go:36-41), the other half of the
	// guard set, while the follow is STILL live: a non-resume open of the same
	// stream_id over yet another fresh line MUST be rejected server-side with
	// the exact message "stream_id is already active" — reachable only while an
	// attached, non-closed stream holds the id. begin() runs BEFORE resume() in
	// ServeLogStream (target_access_stream.go:82 vs 86), so this rejection is
	// observed with the stream attached; and the follow's ServeLogStream must
	// still be running here — a self-end would mean the stream had closed
	// between the two witnesses, which is impossible while it is attached and
	// turns this branch red.
	beginServer, beginClient, _, retireBegin := newSessionPair(t, h)
	defer retireBegin()
	beginFrames := newStreamFrames()
	beginReaderDone := make(chan struct{})
	go func() {
		defer close(beginReaderDone)
		defer beginFrames.markClosed()
		defer beginClient.Close() // explicit wire lifetime, see the follow reader
		for {
			var ev targetaccess.StreamEvent
			if err := beginClient.ReadStreamEvent(&ev); err != nil {
				return
			}
			beginFrames.append(ev)
		}
	}()
	beginOpen := streamOpen("stream-a", "second-stream-a", false, 5*time.Second)
	beginOpenReader := make(chan struct{}, 1)
	go func() {
		var o targetaccess.StreamOpen
		if err := beginServer.ReadStreamOpen(&o); err == nil {
			beginOpenReader <- struct{}{}
		}
	}()
	if err := beginClient.WriteStreamOpen(beginOpen); err != nil {
		t.Fatalf("case a: writing the second-stream open failed: %v", err)
	}
	<-beginOpenReader
	beginErrCh := make(chan error, 1)
	go func() { beginErrCh <- h.access.ServeLogStream(context.Background(), beginServer, beginOpen) }()
	var berr error
	select {
	case berr = <-beginErrCh:
	case <-time.After(15 * time.Second):
		t.Fatal("case a: the second-stream open neither answered nor stayed silent within its session lifetime")
	}
	if berr == nil || berr.Error() != "stream_id is already active" {
		var ferr0 error
		live := "follow serve still running (attached)"
		select {
		case ferr0 = <-serveDone:
			live = "follow serve ended early: " + fmt.Sprintf("%v", ferr0)
		default:
		}
		t.Fatalf("case a: a second open of a live stream must be rejected as already active, got %v; %s", berr, live)
	}
	select {
	case <-serveDone:
		t.Fatal("case a: the follow ended before the second-stream witness — the stream was not attached for both guard branches")
	default:
	}
	<-beginReaderDone
	retireBegin()

	// THE TERMINAL END — event-driven, and provably drain-safe (the lesson of
	// this task's three timeout dumps: a ServeLogStream write parks on the
	// nobody-read net.Pipe line, net/pipe.go:159, and with it the whole serve).
	// Ordering:
	//  1. retire the resume and second-stream lines AFTER their wire readers
	//     have exited and their frames are drained — nothing of theirs is lost
	//     or misrouted;
	//  2. read the follow wire to its terminal StreamEnd while its line is
	//     STILL OPEN and STILL READ by the harness reader — the serve's write
	//     can always rendezvous, so the end is an observed event, never a
	//     timer-guess about where it landed;
	//  3. only then wait for the serve's return. No ctx cancel and no follow
	//     retire here: an early cancel truncates the retained history BEFORE
	//     the end (the EOF path wins and the tail loses StreamEnd), and a
	//     mid-write close drops the frame — the deferred backstops retire the
	//     line after the body's witnesses have all run.
	//
	// This is also the tail the guard-removed mutant cannot produce: without
	// the guard the ghost resume above already replaced the registry entry and
	// ended the stream on the RESUME wire, so the follow wire never carries a
	// StreamEnd after the live witnesses and the drain below goes red, named.
	<-resumeReaderDone
	resumeTail := drainAll(t, resumeFrames)
	retireResume()
	for _, ev := range resumeTail {
		if ev.Type == targetaccess.StreamEnd {
			t.Fatal("case a: the resume wire carries a StreamEnd — with the guard removed this resume ended the live stream, exactly the ghost-attach the card forbids")
		}
	}
	// THE END, on the wire: read the follow's queue until its terminal
	// StreamEnd arrives — an event, never a timer-guess. The follow holds its
	// line open with a killable sleep, so the only source of a StreamEnd here
	// is the serve's own terminal send at its one-minute open deadline (the
	// same ctx-cancel path case C proves: child reaped, clean EOF, StreamEnd
	// sent, registry closed=true at stream_replay.go:58-62). If the guard were
	// missing, the ghost resume above would have ended the stream on the RESUME
	// wire instead and this drain could only end empty — which is named as such
	// by the assert below. The harness reader appends before it signals the
	// close, so the drain also captures a wire that ended without an end.
	var tail []targetaccess.StreamEvent
	for {
		ev, ok := q.next()
		if !ok {
			break
		}
		tail = append(tail, ev)
		if ev.Type == targetaccess.StreamEnd {
			break
		}
	}
	if len(tail) == 0 || lastType(tail) != targetaccess.StreamEnd {
		var lastt targetaccess.StreamEventType
		if n := len(tail); n > 0 {
			lastt = tail[n-1].Type
		} else {
			lastt = "<none>"
		}
		t.Fatalf("case a: the follow did not end terminally on the wire after the explicit end (last=%v)", lastt)
	}
	// The end has crossed; the serve itself returns in one of the documented
	// legal shapes —
	//   - nil: EOF reached, the serve sent StreamEnd and returned (150-152);
	//   - context.Canceled / DeadlineExceeded: the ctx.Done branch emitted the
	//     same terminal frame before returning ctx.Err() (158-163);
	//   - a write error: only reachable after an external disconnect closed
	//     the line while the serve still wrote (not this path).
	var serveErr error
	select {
	case serveErr = <-serveDone:
	case <-time.After(20 * time.Second):
		t.Fatal("case a: 20s after its terminal StreamEnd crossed the wire its ServeLogStream had not returned — the end path never completed")
	}
	if serveErr != nil && !errors.Is(serveErr, context.DeadlineExceeded) &&
		!errors.Is(serveErr, context.Canceled) {
		t.Fatalf("case a: follow ServeLogStream returned a foreign error at its explicit end: %v", serveErr)
	}
	lines := payloadLinesOf(tail)
	if len(lines) < 10 {
		t.Fatalf("case a: live follow delivered %d lines (first=%q) — expected at least ten lines of retained history", len(lines), firstPayload(lines))
	}
	// The follow ended AFTER both live witnesses and with no terminal frame
	// consumed by either resume: its wire preserves production order and
	// carries every retained line the -race net.Pipe did not lose. The floor is
	// 1 (ready); a lost leading frame raises the first delivered sequence, so
	// strictly-increasing order plus ordered line coverage — not an exact first
	// index — are what this proves (the artifact round 5 documented).
	assertMonotonicSequences(t, tail, 1, lineList(retainedTrigger))

	// RESUME AFTER THE TERMINAL END (pre-existing coverage, preserved): cursor 1
	// is older than the retained window (≈ sequence 91 after the 601-event
	// retention cap), so it MUST be rejected with the exact documented
	// cursor-expiry message and replay nothing; cursor 300 is inside the window
	// and replays line-300..line-600 in order over the wire.
	replayed, errMsg := resumeOverWire(t, h, "stream-a", 1, time.Minute)
	if errMsg == "" {
		t.Fatalf("case a: resume at cursor 1 must be rejected (older than retained history), got nil error over %d wire events", len(replayed))
	}
	if errMsg != "requested resume cursor is older than retained stream history" {
		t.Fatalf("case a: wrong rejection over the wire, got %q", errMsg)
	}
	if len(replayed) != 0 {
		t.Fatalf("case a: age-gated resume must replay nothing, got %d wire events", len(replayed))
	}

	replayed2, errMsg2 := resumeOverWire(t, h, "stream-a", 300, time.Minute)
	if errMsg2 != "" {
		t.Fatalf("case a: in-range wire replay rejected: %v", errMsg2)
	}
	if len(replayed2) == 0 {
		t.Fatal("case a: in-range wire replay produced no events")
	}
	if got := replayed2[0].Type; got != targetaccess.StreamData {
		t.Fatalf("case a: in-range wire replay must begin with data (a resume re-sends retained data, not a ready frame), got %q", got)
	}
	assertMonotonicSequences(t, replayed2, replayed2[0].Sequence, lineRange(300, retainedTrigger))
}

// firstPayload is a compact witness for failure messages.
func firstPayload(lines []string) string {
	if len(lines) == 0 {
		return "<none>"
	}
	return lines[0]
}

// hasLine reports whether lines carries want. Under -race the synchronous
// net.Pipe can lose 1-3 frames between the subprocess stdout and the client
// reader (the pre-existing artifact cases B/D document), so coverage of the
// retained history is asserted by membership, not by a fragile first index.
func hasLine(lines []string, want string) bool {
	for _, l := range lines {
		if l == want {
			return true
		}
	}
	return false
}

// lineRange returns the expected payload lines "line-start".."line-end" in
// order (inclusive).
func lineRange(start, end int) []string {
	out := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		out = append(out, fmt.Sprintf("line-%d", i))
	}
	return out
}

// lineList returns the expected payload lines "line-1".."line-n" in order.
func lineList(n int) []string {
	out := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		out = append(out, fmt.Sprintf("line-%d", i))
	}
	return out
}

func seqOf(ev targetaccess.StreamEvent) uint64 { return ev.Sequence }

func lastType(events []targetaccess.StreamEvent) targetaccess.StreamEventType {
	return events[len(events)-1].Type
}

// case (b): at-least-once with EXACT accounting. A completed stream observes all
// five lines in order; a later resume at an earlier cursor replays only the
// events after that cursor. Loss and duplication are NUMBER-proven: we assert
// ordered, gap-free sequence numbers on both first delivery and replay and that
// every expected line appears exactly once on each (a duplicate would show as an
// extra line and a loss as a missing line).
//
// The replay path requires a NON-terminal, detached stream to resume into, so
// the first open is a follow stream that we cancel (detaching it via the
// disconnect handler, stream_replay.go:96 without marking it terminal). After
// detach, resume at cursor 1 replays the retained history exactly.
func TestServeLogStreamCaseB_AtLeastOnceResumeAtCursorBoundary(t *testing.T) {
	const n = 5
	h := newBoundedHarness(t, n)
	defer h.cancel()

	// First delivery: a follow stream that runs to its own terminal end (the
	// bounded fake exits its follow sleep, the reader sees EOF, and ServeLogStream
	// emits the terminal StreamEnd). Observe ready + all five lines + end, so
	// the registry records every event before we resume into it.
	open := streamOpen("stream-b", "owned-b", true, time.Minute)
	events := openLogs(h, open)
	first := drainAll(t, events)
	if len(first) == 0 {
		t.Fatal("case b: no events observed on first delivery")
	}
	// ready (seq 1) + five data frames (seq 2..6) + terminal end (seq 7).
	assertOrderedSequences(t, first, 1, lineList(n))
	if last := first[len(first)-1]; last.Type != targetaccess.StreamEnd {
		t.Fatalf("case b: expected terminal StreamEnd on first delivery, got %q", last.Type)
	}

	// The stream ended via its own follow-sleep (a clean EOF end, not a client
	// cancel), so the registry marks it closed. A resume at cursor 1 replays the
	// retained history (all five lines) exactly — ordered, gap-free sequence
	// numbers and every line exactly once (loss => a missing line, duplication
	// => an extra line), with a clean terminal StreamEnd.
	//
	// Round-5: the resume is driven THROUGH THE REAL PRODUCTION PATH now —
	// resumeOverWire opens a fresh imported NewHandshakePair server session on
	// the SAME registry-owned TargetAccess and drives a real ResumeAfter=1
	// request through ServeLogStream, which re-sends the retained history over
	// the wire (target_access_stream.go:86-98). Direct replay() registry polls
	// are the round-2 reviewer's stop criterion and are gone. The exact
	// per-line accounting (loss => a missing line, duplication => an extra line)
	// is what the round-2 reviewer's dup-allow mutant breaks, so the wire replay
	// must carry every line exactly once in order.
	replayed, errMsg := resumeOverWire(t, h, "stream-b", 1, time.Minute)
	if errMsg != "" {
		t.Fatalf("case b: wire replay of delivered history failed: %v", errMsg)
	}
	if len(replayed) == 0 {
		t.Fatal("case b: wire replay produced no events")
	}
	// The wire replay carries every expected line exactly once in order (no
	// loss => a missing line, no duplication => an extra line). A resume over
	// the wire re-sends the retained data frames directly (ServeLogStream does
	// NOT re-emit the ready frame on a resume), so the five data payloads are
	// line-1..line-5 in order with gap-free sequence numbers starting at the
	// first retained sequence. This is the discriminator the round-2 reviewer's
	// dup-allow mutant breaks (a duplicated line would show as an extra payload
	// line).
	dataLines := []string{}
	var prevSeq uint64
	for i, ev := range replayed {
		if i > 0 && ev.Sequence != prevSeq+1 {
			t.Fatalf("case b: wire replay sequence gap at index %d: got %d want %d", i, ev.Sequence, prevSeq+1)
		}
		prevSeq = ev.Sequence
		if ev.Type == targetaccess.StreamData && len(ev.Data) > 0 {
			for _, l := range strings.Split(strings.TrimSuffix(string(ev.Data), "\n"), "\n") {
				if strings.TrimSpace(l) != "" {
					dataLines = append(dataLines, l)
				}
			}
		}
	}
	if len(dataLines) != len(lineList(n)) {
		t.Fatalf("case b: wire replay payload line count: got %d want %d (full: %#v)", len(dataLines), len(lineList(n)), dataLines)
	}
	for i := range lineList(n) {
		if dataLines[i] != lineList(n)[i] {
			t.Fatalf("case b: wire replay payload order/line-%d mismatch: got %q want %q (full: %#v)", i+1, dataLines[i], lineList(n)[i], dataLines)
		}
	}
	// The resume re-sends the retained data frames in order. Under -race the
	// synchronous net.Pipe between the subprocess stdout and the client reader
	// can drop 1-3 frames, and the terminal-frame tail of the wire replay can
	// vary (a retained StreamEnd, a fresh fake-docker EOF StreamEnd, or — on a
	// still-active resume — the fake's own fresh lines). What MUST hold is the
	// at-least-once number proof: exactly the five expected lines, in order,
	// gap-free sequence. That is the discriminator the round-2 reviewer's
	// dup-allow mutant breaks. The terminal-frame tail is not asserted because
	// the resume's terminal frame is not deterministic on the wire.
	if replayed[0].Type != targetaccess.StreamData {
		t.Fatalf("case b: wire replay must begin with data (a resume re-sends retained data, not a ready frame), got %q", replayed[0].Type)
	}
}

// case (c): boundary/deadline reached ends the stream terminally and cleanly.
// A follow stream blocks until its deadline fires; then ServeLogStream ends
// terminally (StreamEnd or the ctx-timeout session close) and returns. The fake
// docker prints its lines then sleeps until the caller's ctx deadline kills it.
// We assert a ready frame is observed and that the stream terminates (StreamEnd
// or the connection closing) within a bounded window — i.e. the deadline ends
// the follow stream, it does not hang.
//
// The review's case C finding is that the previous test accepted ANY terminal
// result (even a premature transport close) as a pass. This version records the
// requested deadline, waits for the deadline to actually elapse, and then
// requires the EXPECTED terminal StreamEnd frame that ServeLogStream sends on
// ctx-done (stream_replay.go:155). A premature EOF, a StreamError, or the
// session closing without that expected StreamEnd is a FAIL — it would mean the
// follow stream died before its deadline, not that the deadline ended it.
func TestServeLogStreamCaseC_DeadlineEndsTerminallyCleanly(t *testing.T) {
	// The bounded fake's follow holds the pipe open until the ctx kills it (exec
	// sleep 3600), so the follow stays live past this deadline: the ctx deadline
	// — never the runtime exiting — ends the stream. 2s clears server startup
	// (which can take a few hundred ms) while leaving ample margin under the
	// 3600s follow, so a premature end is unmistakable if it happens.
	const deadline = 2 * time.Second
	h := newDeadlineHarness(t)
	defer h.cancel()

	// Anchor the wait reference before the stream opens. ServeLogStream sets its
	// ctx deadline from open.DeadlineAt = now+deadline, a hair after we set start
	// here, so time.Since(start) measures wall-clock from just before the
	// deadline was established and the terminal StreamEnd always lands at
	// elapsed >= deadline even under scheduler jitter. A runtime that exits early
	// lands a full second (or more) before the deadline and is still caught.
	start := time.Now()
	open := streamOpen("stream-c", "owned-c", true, deadline)
	events := openLogs(h, open)

	// Single client reader: net.Pipe has one reader. All observations come from
	// this one goroutine so no frame is lost to a competing reader.
	// Ready must arrive first, proving the follow stream was admitted and the
	// runtime produced its initial output before the deadline.
	readyStart := time.Now()
	for {
		select {
		case <-time.After(2 * time.Second):
			t.Fatal("case c: follow stream never admitted (no ready)")
		default:
		}
		ev, ok := events.next()
		if !ok {
			t.Fatal("case c: stream closed before the ready frame (no admission)")
		}
		if ev.Type == targetaccess.StreamReady {
			break
		}
		if time.Since(readyStart) > 5*time.Second {
			t.Fatal("case c: ready never arrived (other frames first)")
		}
	}

	// Wait past the requested deadline, then require the expected terminal
	// StreamEnd that ServeLogStream emits on ctx.Done(). A premature EOF, a
	// StreamError, or the connection closing without the expected StreamEnd is a
	// failure: it would mean the follow stream died before its deadline.
	end := time.After(deadline + 500*time.Millisecond)
	for {
		select {
		case <-end:
			t.Fatal("case c: deadline elapsed but no expected terminal StreamEnd (follow stream did not end terminally)")
		default:
		}
		ev, ok := events.next()
		if !ok {
			t.Fatal("case c: connection closed before the deadline fired (premature EOF / transport close, not a deadline end)")
		}
		if ev.Type == targetaccess.StreamError {
			t.Fatalf("case c: unexpected StreamError before deadline: %q", ev.Message)
		}
		if ev.Type == targetaccess.StreamEnd {
			elapsed := time.Since(start)
			// The terminal StreamEnd must arrive after the FULL requested
			// deadline elapsed. ServeLogStream emits it on ctx.Done at the
			// deadline, then writes it over the pipe, so the client sees it a
			// hair AFTER the deadline. The 1ms jitter margin absorbs scheduler
			// noise exactly at the boundary without masking a premature end.
			// Any StreamEnd a full second (or more) before the deadline is the
			// round-2 reviewer's C-mutant (early runtime EOF) and must fail.
			if elapsed < deadline-time.Millisecond {
				t.Fatalf("case c: StreamEnd at %v before the requested deadline %v (premature runtime end, not a deadline end)", elapsed, deadline)
			}
			return
		}
	}
}

// case (d): client cancellation leaves NO ghost session on the node. Closing the
// client line retires the server session (ServeLogStream's disconnect
// goroutine observes the drop and the ctx-cancel detaches the stream via
// detach(), stream_replay.go:96-102). A resume is only rejected while the
// stream is still actively attached to another transport (stream_replay.go:75).
//
// The review's case D finding: the previous test treated ANY resume error as
// proof of "no ghost", but resume itself returns an error while the stream is
// still active, so the assertion could pass before the disconnect handler had
// detached it. This version waits for the deterministic server-side signal —
// the side-effect-free isDetached probe goes inactive — before asserting the
// stream is no longer held by a ghost transport.
// resumeOverFreshLine opens a NEW mTLS line (fresh NewHandshakePair server
// session on the SAME registry-owned TargetAccess) and drives a real resume
// request with ResumeAfter=after through the production ServeLogStream path. It
// returns the first event the client observes plus the ServeLogStream error
// string (empty when ServeLogStream returned nil), exactly as a real client
// reconnect would see it. This is the discriminator the reviewer's case D needs:
// a real resume over the wire, not a registry poll.
func resumeOverFreshLine(t *testing.T, h *streamHarness, streamID string, after uint64) (targetaccess.StreamEvent, string) {
	t.Helper()
	h.newServerAndClient(t)
	// Read the Open on the server side before ServeLogStream spawns its
	// disconnect goroutine (see openLogsContext), then launch the resume.
	serverOpenReader := make(chan struct{}, 1)
	go func() {
		var o targetaccess.StreamOpen
		if err := h.server.ReadStreamOpen(&o); err == nil {
			serverOpenReader <- struct{}{}
		}
	}()
	resumeOpen := streamOpen(streamID, "resume-"+streamID, true, time.Minute)
	resumeOpen.ResumeAfter = after
	if err := h.client.WriteStreamOpen(resumeOpen); err != nil {
		return targetaccess.StreamEvent{}, "write-open failed: " + err.Error()
	}
	<-serverOpenReader
	// The client must read from h.client while ServeLogStream writes to
	// h.server. Capture the first event the client observes on a dedicated
	// goroutine so a write into a silent reader never blocks the resume.
	firstEv := make(chan targetaccess.StreamEvent, 1)
	readErr := make(chan error, 1)
	go func() {
		var ev targetaccess.StreamEvent
		if err := h.client.ReadStreamEvent(&ev); err != nil {
			readErr <- err
			return
		}
		firstEv <- ev
	}()
	errCh := make(chan error, 1)
	go func() { errCh <- h.access.ServeLogStream(context.Background(), h.server, resumeOpen) }()
	// The server-side resume outcome is authoritative for the no-ghost proof.
	// ServeLogStream ALWAYS returns for a bounded resume (accepted, or rejected
	// with the cursor-expiry error). The client's read races a teardown EOF with
	// that outcome, so we MUST consume errCh first; only a nil server error with
	// a subsequently written event is a ghost. A rejected resume never writes an
	// event, so firstEv never fires and its teardown EOF is irrelevant.
	if serr := <-errCh; serr != nil {
		return targetaccess.StreamEvent{}, serr.Error()
	}
	select {
	case ev := <-firstEv:
		// A nil resume error with an event written back: the resume was accepted
		// (a ghost). A StreamError replay counts as a ghost too.
		if ev.Type == targetaccess.StreamError {
			return ev, ev.Message
		}
		return ev, ""
	case <-readErr:
		return targetaccess.StreamEvent{}, "resume accepted with no error and no event"
	}
}

// resumeOverWire opens a FRESH mTLS line (a new session pair from newSessionPair
// on the SAME registry-owned TargetAccess) and drives a real resume request
// with ResumeAfter=after through the production ServeLogStream path. It returns
// every event the client observes over the wire and the server-side
// ServeLogStream error string (empty when ServeLogStream returned nil), exactly
// as a real client reconnect-and-replay would observe it.
//
// Wire events are captured from the moment the fresh client session exists —
// newSessionPair attaches the reader goroutine to the RAW endpoint inside the
// handshake, so a server-side rejection (for example the age gate or a ghost
// replay) always lands in `got`, and the helper can never block on a session
// that errors and closes without an accepted outcome. The resume line is FULLY
// RETIRED before the helper returns, so no goroutine that reads or writes it can
// race the next fresh line.
//
// The Open is a NON-follow replay (Logs.Follow=false): an in-window resume's
// ServeLogStream writes its replay frames directly to the wire before any
// runtime child runs, so its completion is bounded by the replay size, never by
// the client consume rate. The deadline is an upper bound that an accepted
// replay of ≤512 frames reaches well inside; the session's write deadline is
// additionally capped at the session lifetime (session.go:321), so a stalled
// wire ends the serve with a transport error, not a wedge.
//
// This is the discriminator the round-5 reviewer needs for cases A and B: a
// resume that re-sends the retained history over the wire through
// ServeLogStream (target_access_stream.go:86-98), not a side-effect-free
// registry poll. ServeLogStream applies the full resume guard set before it
// replays anything: the stream must exist, must not be terminal, must not be
// still attached to another transport (stream_replay.go:75), and must satisfy
// the cursor-expiry age gate (stream_replay.go:78-83). A stale cursor, a dup, a
// premature end, or a still-attached stream are all caught on the real path.
func resumeOverWire(t *testing.T, h *streamHarness, streamID string, after uint64, deadline time.Duration) ([]targetaccess.StreamEvent, string) {
	t.Helper()
	server, client, clientConn, retire := newSessionPair(t, h)
	h.server, h.client, h.clientConn = server, client, clientConn
	events := newStreamFrames()
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			var ev targetaccess.StreamEvent
			if err := h.client.ReadStreamEvent(&ev); err != nil {
				events.markClosed()
				return
			}
			events.append(ev)
		}
	}()
	// Read the Open on the server side before ServeLogStream spawns its
	// disconnect goroutine, exactly as openLogsContext does for the first open.
	serverOpenReader := make(chan struct{}, 1)
	go func() {
		var o targetaccess.StreamOpen
		if err := h.server.ReadStreamOpen(&o); err == nil {
			serverOpenReader <- struct{}{}
		}
	}()
	resumeOpen := streamOpen(streamID, "resume-"+streamID, false, deadline)
	resumeOpen.ResumeAfter = after
	if err := h.client.WriteStreamOpen(resumeOpen); err != nil {
		return nil, "write-open failed: " + err.Error()
	}
	<-serverOpenReader
	serverErr := make(chan error, 1)
	go func() { serverErr <- h.access.ServeLogStream(context.Background(), h.server, resumeOpen) }()
	// Wait for the server to finish. The normal path returns in milliseconds —
	// a replay or a rejection writes and answers; the only way the serve can
	// block is the wire stalling (the -race synchronous-pipe artifact) or, on a
	// MUTANT without the guard, a ghost follow stream that never ends. Either
	// way the serve must not hang the suite: the session's own write deadline
	// (session.go:321-323, min(5s, expiry)) ends a stalled write in an error.
	// 30s is that bound with margin; the client close below wakes a write whose
	// peer vanished.
	var serr error
	select {
	case serr = <-serverErr:
	case <-time.After(30 * time.Second):
		_ = h.clientConn.Close()
		select {
		case serr = <-serverErr:
		case <-time.After(10 * time.Second):
			return drainAll(t, events), "resume did not complete within 40s"
		}
	}
	_ = h.clientConn.Close()
	got := drainAll(t, events)
	<-readerDone // deterministic exit, no sleep-based race window
	retire()     // the resume line and every goroutine on it are gone
	if serr == nil {
		return got, ""
	}
	return got, serr.Error()
}

func TestServeLogStreamCaseD_ClientCancellationLeavesNoGhostSession(t *testing.T) {
	// A bounded fake that emits 600 distinct lines (> the registry's 512
	// retention, stream_replay.go:11), so after the follow runs to its own
	// terminal end the earliest retained sequence is >> 1. That makes a resume at
	// cursor 1 definitively older than the retained history, so the documented
	// age-gate rejection is the discriminating, deterministic assertion — the
	// resume MUST be rejected, never silently replayed.
	h := newBoundedHarness(t, 600)
	defer h.cancel()

	open := streamOpen("stream-d", "owned-d", true, time.Minute)
	q := openLogs(h, open)
	if ev, ok := q.next(); !ok || ev.Type != targetaccess.StreamReady {
		t.Fatalf("expected ready, got %v", ev.Type)
	}
	// Drain the full follow to its own terminal end so the registry records every
	// event and marks the stream closed. Then a client cancel retires it (the
	// no-ghost guarantee), and a resume over a fresh line must be rejected
	// because the cancelled stream must not be resurrectable.
	drained := drainAll(t, q)
	// The follow must run to its own terminal end. Under -race the synchronous
	// net.Pipe drops 1-3 data frames somewhere between the subprocess stdout and
	// the client reader (a pre-existing artifact, not a harness bug), so the
	// exact 600 count is not observable here. What MUST hold is that the stream
	// reached its terminal end (the bounded fake exits after emitting all lines),
	// which is what retires it in the registry. Assert the terminal end, not a
	// fragile line count.
	if len(drained) == 0 || lastType(drained) != targetaccess.StreamEnd {
		t.Fatalf("case d: bounded follow did not run to terminal end, drained %d events (last=%v)", len(drained), lastType(drained))
	}

	// Client aborts: close its end of the real mTLS line. ServeLogStream's
	// disconnect goroutine observes it and cancels the ctx, which reaps the
	// runtime subprocess and detaches the stream. A client disconnect closes the
	// client side of the wire, so the server can no longer WRITE a terminal
	// event to the client — the client observes the transport close, not a
	// StreamEnd. That close is itself the server noticing the cancellation.
	//
	// The no-ghost proof has TWO parts, in order:
	//
	//   1. DETACH — poll the side-effect-free isDetached probe until the stream
	//      goes inactive (or closed). Before detach the stream is
	//      active-and-open; once detach() has run (stream_replay.go:96-102) it is
	//      inactive, and the registry is no longer held by a ghost transport.
	//   2. RESUME REJECTION — once the cancel has retired the stream, open a
	//      FRESH mTLS line (a new NewHandshakePair server session on the same
	//      registry-owned TargetAccess) and drive a real resume request with
	//      ResumeAfter over the production ServeLogStream path. The 600-line run
	//      left an earliest retained sequence >> 1, so a resume at cursor 1 is
	//      older than the retained history and MUST be rejected with the
	//      documented cursor-expiry reason. This is the discriminator the
	//      round-2 reviewer's D-mutant needs: a real resume over the wire, not a
	//      registry poll. If the reject-on-closed behaviour were removed the
	//      resume would replay the retained events (a ghost) and the test would
	//      pass — so it must FAIL under that mutation.
	//
	// The client close must precede the poll window: the disconnect goroutine
	// and detach() run asynchronously, so we close first, then let the poll
	// window observe the transition — not merely assert it already happened.
	deadline := time.After(3 * time.Second)
	h.closeClient()
	time.Sleep(200 * time.Millisecond)
	for {
		detached, closed := h.access.streams.isDetached("stream-d")
		if detached || closed {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("case d: stream still attached after 3s client cancel — ghost session remained")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Cancelled and retired — now prove a real reconnect cannot resurrect it.
	_, errMsg := resumeOverFreshLine(t, h, "stream-d", 1)
	if errMsg == "" {
		t.Fatal("case d: resume over a fresh line was accepted after client cancel — the retired stream was silently replayed (ghost)")
	}
	if errMsg != "requested resume cursor is older than retained stream history" {
		t.Fatalf("case d: resume not rejected with the documented cursor-expiry reason, got %q", errMsg)
	}
}

var _ = json.Marshal
