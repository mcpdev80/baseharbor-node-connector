//go:build linux

package targetaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func admissionScope() NodeIdentity {
	return NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111", TargetID: "target-a", NodeID: "node-a", Runtime: "docker", Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"}
}

func admissionRequest(id string) Request {
	now := time.Now().UTC()
	return Request{ContractVersion: ContractVersion, ProtocolVersion: ProtocolVersion, RequestID: id, CorrelationID: "execution-a", TargetID: "target-a", Operation: OpContainerStop, IssuedAt: now, DeadlineAt: now.Add(time.Minute), Payload: json.RawMessage(`{"resource_id":"owned-a"}`)}
}

func TestDurableAdmissionAllowsOneConcurrentSideEffectAcrossStoreInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport")
	first, err := NewAdmissionJournal(path, admissionScope())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewAdmissionJournal(path, admissionScope())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	request := admissionRequest("request-race")
	var successes atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			journal := first
			if index%2 == 1 {
				journal = second
			}
			err := journal.Admit(context.Background(), request)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrReplayAmbiguous) {
				t.Errorf("unexpected race result: %v", err)
			}
		}(i)
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("duplicate admission: %d", successes.Load())
	}
}

func TestAdmissionSurvivesRestartRejectsConflictsAndStoresNoPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport")
	journal, err := NewAdmissionJournal(path, admissionScope())
	if err != nil {
		t.Fatal(err)
	}
	request := admissionRequest("request-restart")
	if err := journal.Admit(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = NewAdmissionJournal(path, admissionScope())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if err := journal.Admit(context.Background(), request); !errors.Is(err, ErrReplayAmbiguous) {
		t.Fatalf("restart replay: %v", err)
	}
	conflict := request
	conflict.Payload = json.RawMessage(`{"resource_id":"foreign-SECRET-CREDENTIAL"}`)
	if err := journal.Admit(context.Background(), conflict); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("content conflict: %v", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var record map[string]any
		if len(data) == 0 {
			continue
		}
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{"payload", "argv", "environment", "result", "error", "token", "private_key"} {
			if _, ok := record[field]; ok {
				t.Fatalf("sensitive input/result persisted: %s", field)
			}
		}
	}
}

func TestAdmissionFailsClosedOnInterruptedRecordsScopeChangesAndQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport")
	journal, err := NewAdmissionJournal(path, admissionScope())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	request := admissionRequest("interrupted")
	key := sha256.Sum256([]byte("request/" + request.RequestID))
	if err := os.WriteFile(filepath.Join(path, hex.EncodeToString(key[:])+".admission"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := journal.Admit(context.Background(), request); !errors.Is(err, ErrAdmissionJournal) {
		t.Fatalf("partial record retried: %v", err)
	}
	foreign := admissionScope()
	foreign.TargetID = "target-b"
	foreign.Identity = "spiffe://baseharbor/platform/connectors/" + foreign.TenantID + "/" + foreign.TargetID + "/" + foreign.NodeID
	if other, err := NewAdmissionJournal(path, foreign); err == nil {
		other.Close()
		t.Fatal("persistent node scope was rebound")
	}
	journal.maxRecords = 2
	if err := journal.Admit(context.Background(), admissionRequest("second")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Admit(context.Background(), admissionRequest("third")); !errors.Is(err, ErrAdmissionJournal) {
		t.Fatalf("unbounded journal accepted: %v", err)
	}
}

func TestAdmissionRejectsExpiredForeignAndCancelledRequestsBeforePersistence(t *testing.T) {
	journal, err := NewAdmissionJournal(filepath.Join(t.TempDir(), "transport"), admissionScope())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	for _, variant := range []string{"expired", "target", "cancelled"} {
		request := admissionRequest(variant)
		ctx := context.Background()
		if variant == "expired" {
			request.DeadlineAt = time.Now().Add(-time.Second)
		}
		if variant == "target" {
			request.TargetID = "foreign"
		}
		if variant == "cancelled" {
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			ctx = cancelled
		}
		if err := journal.Admit(ctx, request); !errors.Is(err, ErrAdmissionJournal) {
			t.Fatalf("%s admitted: %v", variant, err)
		}
	}
}

func TestTerminalAdmissionCannotReopenOrChangeTheAdmittedPTY(t *testing.T) {
	journal, err := NewAdmissionJournal(filepath.Join(t.TempDir(), "transport"), admissionScope())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	open := StreamOpen{ContractVersion: ContractVersion, ProtocolVersion: ProtocolVersion, StreamID: "terminal-a", CorrelationID: "execution-a", TargetID: "target-a", ResourceID: "owned-a", Kind: StreamTerminal, DeadlineAt: time.Now().UTC().Add(time.Minute), Terminal: &TerminalStreamOptions{Rows: 24, Cols: 80, Argv: []string{"/bin/sh"}}}
	if err := journal.AdmitTerminal(context.Background(), open); err != nil {
		t.Fatal(err)
	}
	if err := journal.AdmitTerminal(context.Background(), open); !errors.Is(err, ErrReplayAmbiguous) {
		t.Fatalf("PTY replay: %v", err)
	}
	open.Terminal.User = "foreign"
	if err := journal.AdmitTerminal(context.Background(), open); !errors.Is(err, ErrReplayConflict) {
		t.Fatalf("PTY content conflict: %v", err)
	}
}

func TestJournalRejectsSharedOrSymlinkRoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if journal, err := NewAdmissionJournal(path, admissionScope()); err == nil {
		journal.Close()
		t.Fatal("shared root accepted")
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if journal, err := NewAdmissionJournal(link, admissionScope()); err == nil {
		journal.Close()
		t.Fatal("symlink root accepted")
	}
}
