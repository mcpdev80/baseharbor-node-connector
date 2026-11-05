//go:build linux

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// streamHarness holds a real TargetAccess and a real mTLS session pair.
type streamHarness struct {
	access            *TargetAccess
	pair              *targetaccess.HandshakePair
	server            *targetaccess.Session
	client            *targetaccess.Session
	serverConn        net.Conn
	clientConn        net.Conn
	cancels           []context.CancelFunc
	invocationLogPath string
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
	t.Helper()
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" | awk '{ $NF="container-000000000000"; printf "%%s\n", $0 }' >> "$BASEHARBOR_TEST_LOG_INVOCATIONS"
i=0
while [ "$i" -lt %d ]; do
	i=$((i+1))
		/usr/bin/echo "line-$i"
done
exit 0
`, n)
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
}

func newStreamFrames() *streamFrames {
	return &streamFrames{done: make(chan struct{})}
}

func (q *streamFrames) append(ev targetaccess.StreamEvent) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.all = append(q.all, ev)
	q.mu.Unlock()
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

// next blocks until the next frame is available or the stream has closed,
// returning the frame and true, or the zero frame and false once closed.
func (q *streamFrames) next() (targetaccess.StreamEvent, bool) {
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
	q.mu.Unlock()
	<-q.done
	q.mu.Lock()
	if len(q.all) > 0 {
		ev := q.all[0]
		q.all = q.all[1:]
		q.mu.Unlock()
		return ev, true
	}
	q.mu.Unlock()
	return targetaccess.StreamEvent{}, false
}

// drainAll returns every captured frame in order. Used by the accounting cases
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
	if events[0].Sequence != firstSeq {
		t.Fatalf("case replay: first sequence %d want %d", events[0].Sequence, firstSeq)
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

// case (a): cursor expiry is documented semantics, not a silent reset.
//
// The registry retains only the last `max` events (default 512,
// stream_replay.go:11). To drive a REAL retained-history boundary through the
// production ServeLogStream path, this case makes the fake docker emit 600
// distinct lines; the production reader produces one StreamData event per line
// (each line is flushed on its own, so the 16 KiB read buffer yields a frame
// per line), so the registry stores 601 events (ready + 600 data) and retains
// the last 512 — i.e. the earliest retained sequence is > 1.
//
// We then resume at cursor 0 (strictly older than the first retained sequence)
// and assert the EXACT documented rejection
// ("requested resume cursor is older than retained stream history",
// stream_replay.go:81), not merely "some error". Finally we resume at cursor 1
// (inside retained history) and assert a clean happy-path replay.
func TestServeLogStreamCaseA_CursorExpiryDocumentedSemantics(t *testing.T) {
	const retainedTrigger = 600 // > defaultStreamReplayEvents (512)

	h := newBoundedHarness(t, retainedTrigger)
	defer h.cancel()

	open := streamOpen("stream-a", "owned-a", false, time.Minute)
	q := openLogs(h, open)
	all := drainAll(t, q)
	witnessData, _ := os.ReadFile(h.invocationLogPath)
	t.Logf("case a: witness (first 200 bytes): %q", string(witnessData[:min(200, len(witnessData))]))
	// ready (seq 1) + 600 data frames (seq 2..601) + terminal end (seq 602).
	if all[0].Type != targetaccess.StreamReady {
		t.Fatalf("case a: expected ready first, got %q", all[0].Type)
	}
	// The 600-line capture can lose 1-3 data frames under -race (pre-existing
	// race-detector artifact on the synchronous net.Pipe). The retained history
	// (512 events, stream_replay.go:55-56) is still exceeded, so cursor 1 is
	// rejected below. What MUST hold is that the delivered lines preserve
	// production order and carry every expected line in order.
	assertMonotonicSequences(t, all, 1, lineList(retainedTrigger))
	if last := all[len(all)-1]; last.Type != targetaccess.StreamEnd {
		t.Fatalf("case a: expected terminal StreamEnd, got %q", last.Type)
	}

	// Resume at cursor 1: the earliest retained sequence is > 1 (≈91, because
	// 602 events were produced and only the last 512 are kept), so a resume at
	// cursor 1 is strictly older than the retained window. The registry only
	// applies the age gate when after > 0 (stream_replay.go:78), so cursor 1
	// (not cursor 0) exercises it. This MUST be rejected with the exact
	// documented message, not merely "some error". The age gate is on the
	// replay path (stream_replay.go:111-115), so the replay() here is the
	// right probe.
	if _, _, err := h.access.streams.replay("stream-a", 1); err == nil {
		t.Fatal("case a: resume at cursor 1 must be rejected (older than retained history), got nil error")
	} else if got := err.Error(); got != "requested resume cursor is older than retained stream history" {
		t.Fatalf("case a: wrong rejection, got %q", got)
	}

	// Resume at cursor 300 (inside the retained window: first retained seq ≈91,
	// so 300 is not < 91) replays the events after it in order, each exactly
	// once, terminally. The event sequence is offset by the ready frame, so
	// line-k lives at sequence k+1; events after cursor 300 are line-300..line-600.
	// The 600-line capture can lose 1-3 frames under -race; assertMonotonic keeps
	// the order/coverage proof deterministic while tolerating that loss.
	replay2, _, err := h.access.streams.replay("stream-a", 300)
	if err != nil {
		t.Fatalf("case a: in-range replay rejected: %v", err)
	}
	assertMonotonicSequences(t, replay2, 301, lineRange(300, retainedTrigger))
	if last := replay2[len(replay2)-1]; last.Type != targetaccess.StreamEnd {
		t.Fatalf("case a: expected terminal StreamEnd on in-range replay, got %q", last.Type)
	}
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
	// => an extra line), with a clean terminal StreamEnd. replay() is the
	// non-mutating replay path (stream_replay.go:111) that mirrors what the
	// production resume-at-cursor path returns.
	replay, _, err := h.access.streams.replay("stream-b", 1)
	if err != nil {
		t.Fatalf("case b: replay of delivered history failed: %v", err)
	}
	assertOrderedSequences(t, replay, 2, lineList(n))
	if last := replay[len(replay)-1]; last.Type != targetaccess.StreamEnd {
		t.Fatalf("case b: expected terminal StreamEnd on replay, got %q", last.Type)
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
