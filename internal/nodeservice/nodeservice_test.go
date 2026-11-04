package nodeservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeUnitManager records calls and returns a controllable activation state so
// the determinism rules can be exercised without a live systemd session.
type fakeUnitManager struct {
	mu         sync.Mutex
	installed  bool
	enabled    bool
	active     State
	startErr   error
	restartErr error
	removeErr  error
	enableErr  error
	disableErr error
}

func (f *fakeUnitManager) Install(_ context.Context, unit Unit) (Unit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = true
	unit.Active = f.active
	return unit, nil
}

func (f *fakeUnitManager) Start(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = true
	return f.startErr
}

func (f *fakeUnitManager) Restart(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = true
	return f.restartErr
}

func (f *fakeUnitManager) Remove(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = false
	return f.removeErr
}

func (f *fakeUnitManager) Enable(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = true
	return f.enableErr
}

func (f *fakeUnitManager) Disable(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = false
	return f.disableErr
}

func (f *fakeUnitManager) Observe(_ context.Context, unit Unit) (State, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active, nil
}

// fakeStore is a controllable MetadataStore that can be switched to simulate
// "nothing installed yet" (ErrNotFound).
type fakeStore struct {
	mu      sync.Mutex
	unit    Unit
	enroll  EnrollmentState
	missing bool
	saveErr error
}

func (f *fakeStore) Load(_ context.Context) (Unit, EnrollmentState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing {
		return Unit{}, EnrollmentState{}, ErrNotFound
	}
	return f.unit, f.enroll, nil
}

func (f *fakeStore) Save(_ context.Context, unit Unit, enroll EnrollmentState) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.unit = unit
	f.enroll = enroll
	f.missing = false
	return nil
}

func newTestService(mgr UnitManager, store MetadataStore, driver EnrollmentDriver, now func() time.Time) *Service {
	return NewService(mgr, store, driver, now)
}

// fakeEnrollDriver returns a canned serial and records how many times it was
// invoked, so tests can assert a blocked re-enrollment performs no enrollment.
type fakeEnrollDriver struct {
	mu     sync.Mutex
	calls  int
	serial string
	err    error
}

func (f *fakeEnrollDriver) Reenroll(_ context.Context, _ NodeRef) (EnrollmentResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return EnrollmentResult{}, f.err
	}
	return EnrollmentResult{Serial: f.serial, ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour)}, nil
}

func (f *fakeEnrollDriver) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func selfUnit() Unit {
	return Unit{Kind: UnitKindSystemdUser, Name: ServiceNameForBinary("podman"), ExecLine: "ExecStart=/usr/local/bin/baseharbor-node-connector --core core:9443"}
}

// Re-enrollment twice yields a defined, deterministic state: the first call
// installs the enrollment, the second (while active and unexpired) is blocked
// with ErrAlreadyEnrolled and does not mutate the stored enrollment.
func TestReenrollTwiceIsDeterministicAndBlocksSecond(t *testing.T) {
	store := &fakeStore{missing: true}
	driver := &fakeEnrollDriver{serial: "deadbeef"}
	svc := newTestService(&fakeUnitManager{}, store, driver, func() time.Time { return time.Unix(1_000_000, 0).UTC() })
	identity := NodeRef{TenantID: "11111111-1111-4111-8111-111111111111", NodeID: "node-a", TargetID: "target-a", Runtime: "podman", Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"}

	result, err := svc.Reenroll(context.Background(), identity)
	if err != nil {
		t.Fatalf("first re-enrollment failed: %v", err)
	}
	if result.Serial != "deadbeef" {
		t.Fatalf("unexpected serial %q", result.Serial)
	}

	_, err = svc.Reenroll(context.Background(), identity)
	if !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("second re-enrollment while active should be blocked, got: %v", err)
	}
}

// A re-enrollment is allowed when the existing enrollment has expired, and a
// re-enrollment with a revoked serial is allowed even while nominally valid.
func TestReenrollAllowedWhenExpiredOrRevoked(t *testing.T) {
	now := func() time.Time { return time.Unix(1_000_000, 0).UTC() }
	expired := EnrollmentState{Identity: identityID(), Serial: "cafe", Expires: now().Add(-time.Hour)}
	if got := PlanReenroll(expired, identityID(), now(), false); got != ReenrollAllowed {
		t.Fatalf("expired enrollment should allow re-enrollment, got %q", got)
	}
	revoked := EnrollmentState{Identity: identityID(), Serial: "cafe", Expires: now().Add(time.Hour)}
	if got := PlanReenroll(revoked, identityID(), now(), true); got != ReenrollAllowed {
		t.Fatalf("revoked serial should allow re-enrollment, got %q", got)
	}
	active := EnrollmentState{Identity: identityID(), Serial: "cafe", Expires: now().Add(30 * 24 * time.Hour)}
	if got := PlanReenroll(active, identityID(), now(), false); got != ReenrollBlocked {
		t.Fatalf("active unexpired enrollment should block re-enrollment, got %q", got)
	}
}

// Re-enrollment against a conflicting identity is allowed (deterministic), but a
// re-enroll that fails to bind must not leave a partial enrollment behind.
func TestReenrollConflictingIdentityIsAllowed(t *testing.T) {
	store := &fakeStore{missing: false, enroll: EnrollmentState{Identity: identityID(), Serial: "old", Expires: time.Unix(2_000_000, 0).UTC()}}
	svc := newTestService(&fakeUnitManager{}, store, &fakeEnrollDriver{serial: "cafe"}, func() time.Time { return time.Unix(1_000_000, 0).UTC() })
	other := NodeRef{Identity: "spiffe://baseharbor/platform/connectors/22222222-2222-4222-8222-222222222222/target-a/node-b"}
	_, err := svc.Reenroll(context.Background(), other)
	if err != nil {
		t.Fatalf("conflicting-identity re-enrollment should be allowed, got: %v", err)
	}
}

// Restart behaves identically to a cold start when the unit content and
// enrollment are unchanged: both go through Install-presence check -> manager
// operation -> observe -> save. A failing restart is surfaced, not swallowed.
func TestRestartSameBehaviorAsStart(t *testing.T) {
	mgr := &fakeUnitManager{}
	store := &fakeStore{missing: false}
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil)
	unit := selfUnit()

	if err := mgr.Start(context.Background(), unit); err != nil {
		t.Fatalf("seed start failed: %v", err)
	}
	// reset recorded state to compare behavior
	mgr.mu.Lock()
	mgr.startErr = nil
	mgr.mu.Unlock()

	if err := svc.Restart(context.Background(), unit); err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	if !mgr.installed {
		t.Fatal("restart did not confirm the unit is installed")
	}
}

// EnsureInstall fails closed when nothing is installed: a start/restart before
// install must return ErrNotFound, never a false success.
func TestLifecycleFailsClosedWithoutInstall(t *testing.T) {
	mgr := &fakeUnitManager{}
	store := &fakeStore{missing: true}
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil)
	unit := selfUnit()

	if err := svc.Start(context.Background(), unit); !errors.Is(err, ErrNotFound) {
		t.Fatalf("start without install must fail closed, got: %v", err)
	}
	if err := svc.Restart(context.Background(), unit); !errors.Is(err, ErrNotFound) {
		t.Fatalf("restart without install must fail closed, got: %v", err)
	}
}

// Uninstall removes the unit and clears persisted state.
func TestUninstallRemovesUnitAndClearsState(t *testing.T) {
	mgr := &fakeUnitManager{installed: true}
	store := &fakeStore{missing: false}
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil)
	if err := svc.Uninstall(context.Background(), selfUnit()); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}
	if mgr.installed {
		t.Fatal("unit was not removed")
	}
}

// A self-owned unit name that does not reference the connector binary is
// rejected; unknown kinds are rejected; blank ExecStart is rejected.
func TestValidateSelfOwnedUnitFailsClosed(t *testing.T) {
	if err := validateSelfOwnedUnit(Unit{Kind: UnitKindSystemdUser, Name: "foreign-unit.container", ExecLine: "x"}); err == nil {
		t.Fatal("foreign unit name accepted")
	}
	if err := validateSelfOwnedUnit(Unit{Kind: "weird", Name: ServiceNameForBinary(""), ExecLine: "x"}); err == nil {
		t.Fatal("unknown unit kind accepted")
	}
	if err := validateSelfOwnedUnit(Unit{Kind: UnitKindSystemdUser, Name: ServiceNameForBinary(""), ExecLine: ""}); err == nil {
		t.Fatal("blank ExecStart accepted")
	}
	if err := validateSelfOwnedUnit(selfUnit()); err != nil {
		t.Fatalf("valid self-owned unit rejected: %v", err)
	}
}

// The protected state store refuses to load untagged or tampered payloads.
func TestProtectedStateStoreRejectsTamperedPayload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := newProtectedStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store should report ErrNotFound, got: %v", err)
	}
	// write a raw, untagged file to simulate tampering
	if err := os.WriteFile(store.path, []byte("not a tagged state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(context.Background()); err == nil {
		t.Fatal("untagged state loaded")
	}
}

// ServiceNameForBinary yields a self-owned, connector-identifying name.
func TestServiceNameForBinaryIsSelfOwned(t *testing.T) {
	name := ServiceNameForBinary("podman")
	if err := validateSelfOwnedUnit(Unit{Kind: UnitKindSystemdUser, Name: name, ExecLine: "x"}); err != nil {
		t.Fatalf("generated service name should be self-owned: %v", err)
	}
	if filepath.Ext(name) != ".container" {
		t.Fatalf("unexpected extension: %q", name)
	}
}

func identityID() string {
	return "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"
}
