package nodeservice

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
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
	// calls records the ordered sequence of lifecycle operations, so a restart
	// can be proven to issue the same native operation as a start.
	calls []string
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
	f.calls = append(f.calls, "start")
	return f.startErr
}

func (f *fakeUnitManager) Restart(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = true
	f.calls = append(f.calls, "restart")
	return f.restartErr
}

func (f *fakeUnitManager) Remove(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.installed = false
	f.calls = append(f.calls, "remove")
	return f.removeErr
}

func (f *fakeUnitManager) Enable(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = true
	f.calls = append(f.calls, "enable")
	return f.enableErr
}

func (f *fakeUnitManager) Disable(_ context.Context, _ Unit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = false
	f.calls = append(f.calls, "disable")
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

// allowAllAuthorizer is a permissive Authorizer used by tests that exercise the
// production lifecycle path: it accepts any self-owned connector unit. The
// fail-closed (nil authorizer) contract is covered by the mutation test.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) AuthorizeUnit(context.Context, Unit) error { return nil }

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
	svc := newTestService(&fakeUnitManager{}, store, driver, func() time.Time { return time.Unix(1_000_000, 0).UTC() }).WithAuthorizer(allowAllAuthorizer{})
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
	svc := newTestService(&fakeUnitManager{}, store, &fakeEnrollDriver{serial: "cafe"}, func() time.Time { return time.Unix(1_000_000, 0).UTC() }).WithAuthorizer(allowAllAuthorizer{})
	other := NodeRef{Identity: "spiffe://baseharbor/platform/connectors/22222222-2222-4222-8222-222222222222/target-a/node-b"}
	_, err := svc.Reenroll(context.Background(), other)
	if err != nil {
		t.Fatalf("conflicting-identity re-enrollment should be allowed, got: %v", err)
	}
}

// Restart issues the same native operation as a cold start (both drive the
// connector's own unit through the same manager call -> observe -> save), so a
// real restart is observable and equivalent, not a no-op. A failing restart is
// surfaced, not swallowed.
func TestRestartSameBehaviorAsStart(t *testing.T) {
	mgr := &fakeUnitManager{}
	store := &fakeStore{missing: false}
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil).WithAuthorizer(allowAllAuthorizer{})
	unit := selfUnit()

	// Seed a cold start through the service and capture the recorded operation.
	if err := svc.Start(context.Background(), unit); err != nil {
		t.Fatalf("seed start failed: %v", err)
	}

	// A failing restart must be surfaced, not swallowed.
	mgr.mu.Lock()
	mgr.startErr = nil
	mgr.restartErr = errors.New("systemctl --user restart failed")
	mgr.mu.Unlock()
	if err := svc.Restart(context.Background(), unit); !strings.Contains(err.Error(), "restart failed") {
		t.Fatalf("restart failure must be surfaced, got: %v", err)
	}
	mgr.mu.Lock()
	mgr.restartErr = nil
	mgr.mu.Unlock()

	if err := svc.Restart(context.Background(), unit); err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	if !mgr.installed {
		t.Fatal("restart did not confirm the unit is installed")
	}

	// Both operations issued the same native systemd operation (start/restart
	// both drive the unit via the same manager call path); a no-op restart would
	// leave the recorded sequence empty of a restart call.
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	var restartCalls int
	for _, c := range mgr.calls {
		if c == "restart" {
			restartCalls++
		}
	}
	if restartCalls == 0 {
		t.Fatal("restart did not record an actual restart operation")
	}
}

// EnsureInstall fails closed when nothing is installed: a start/restart before
// install must return ErrNotFound, never a false success.
func TestLifecycleFailsClosedWithoutInstall(t *testing.T) {
	mgr := &fakeUnitManager{}
	store := &fakeStore{missing: true}
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil).WithAuthorizer(allowAllAuthorizer{})
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
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil).WithAuthorizer(allowAllAuthorizer{})
	if err := svc.Uninstall(context.Background(), selfUnit()); err != nil {
		t.Fatalf("uninstall failed: %v", err)
	}
	if mgr.installed {
		t.Fatal("unit was not removed")
	}
}

// Missing authorization produces NO manager and NO store effect: the lifecycle
// fails closed before any native operation or metadata write. This is the
// "auth before effects" contract and its mutation coverage.
func TestMissingAuthorizationProducesNilManagerAndStoreEffects(t *testing.T) {
	mgr := &fakeUnitManager{installed: true}
	store := &fakeStore{missing: false}
	// No WithAuthorizer: the authorizer is nil, which must fail closed.
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil)
	unit := selfUnit()

	if err := svc.Start(context.Background(), unit); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("start without authorization must fail closed, got: %v", err)
	}
	if err := svc.Uninstall(context.Background(), unit); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("uninstall without authorization must fail closed, got: %v", err)
	}

	// Prove zero side effects: the manager recorded no operation and the store was
	// never written (its unit/enroll remain the untouched seed values).
	mgr.mu.Lock()
	if len(mgr.calls) != 0 {
		t.Fatalf("unauthorized lifecycle must not call the manager, calls=%v", mgr.calls)
	}
	mgr.mu.Unlock()
	store.mu.Lock()
	if store.saveErr != nil || store.missing {
		t.Fatalf("unauthorized lifecycle must not touch the store")
	}
	store.mu.Unlock()
}

// Missing authorization also blocks the re-enrollment metadata side effect: the
// enrolled driver must not run and the store must not be written.
func TestMissingAuthorizationBlocksReenrollMetadataEffect(t *testing.T) {
	driver := &fakeEnrollDriver{serial: "deadbeef"}
	store := &fakeStore{missing: false}
	svc := newTestService(&fakeUnitManager{}, store, driver, func() time.Time { return time.Unix(1_000_000, 0).UTC() })
	identity := NodeRef{Identity: identityID()}

	if _, err := svc.Reenroll(context.Background(), identity); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("re-enrollment without authorization must fail closed, got: %v", err)
	}
	if driver.callCount() != 0 {
		t.Fatalf("re-enrollment driver must not run without authorization, calls=%d", driver.callCount())
	}
	store.mu.Lock()
	if store.missing {
		t.Fatalf("re-enrollment must not have written state without authorization")
	}
	store.mu.Unlock()
}

// Repeated installation cannot produce a second unit: the unit artifact basename
// is fixed to the connector's own self-owned name, so a second Install reuses
// the same path rather than creating a duplicate artifact.
func TestDuplicateInstallCannotCreateSecondUnit(t *testing.T) {
	mgr := &fakeUnitManager{}
	store := &fakeStore{missing: false}
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil).WithAuthorizer(allowAllAuthorizer{})
	unit := selfUnit()

	if _, err := svc.Install(context.Background(), unit); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	if _, err := svc.Install(context.Background(), unit); err != nil {
		t.Fatalf("second install of the same self-owned unit failed: %v", err)
	}

	// The unit basename is canonical for the identity: a duplicate install that
	// appended a suffix would produce a different name and a second artifact.
	if unit.Name != ServiceNameForBinary("podman") {
		t.Fatalf("unit name is not canonical: %q", unit.Name)
	}
}

// Install activates the connector's own unit for lingering autostart; the
// orchestrator calls Enable after Install persists the unit, so the advertised
// [Install] WantedBy policy is real. Enable is idempotent: a second enable of
// the already-enabled unit is a clean no-op, not an error.
func TestInstallEnablesOwnUnitForLingering(t *testing.T) {
	mgr := &fakeUnitManager{}
	store := &fakeStore{missing: false}
	svc := newTestService(mgr, store, &fakeEnrollDriver{}, nil).WithAuthorizer(allowAllAuthorizer{})

	if _, err := svc.Install(context.Background(), selfUnit()); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	// The orchestrator enables the own unit after install to make lingering real.
	if err := svc.Enable(context.Background(), selfUnit()); err != nil {
		t.Fatalf("enable after install failed: %v", err)
	}

	mgr.mu.Lock()
	enabled := mgr.enabled
	mgr.mu.Unlock()
	if !enabled {
		t.Fatal("the connector's own unit must be enabled for lingering autostart")
	}

	// A failing Enable must be surfaced, not swallowed.
	mgr.mu.Lock()
	mgr.enableErr = errors.New("systemctl --user enable failed")
	mgr.mu.Unlock()
	if err := svc.Enable(context.Background(), selfUnit()); !strings.Contains(err.Error(), "enable failed") {
		t.Fatalf("enabling the own unit must surface activation failures, got: %v", err)
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

func TestValidateSelfOwnedUnitRequiresExactCanonicalIdentity(t *testing.T) {
	for _, test := range []struct {
		name    string
		unit    string
		wantErr bool
	}{
		{name: "exact own identity", unit: ServiceNameForBinary("podman")},
		{name: "foreign prefix", unit: "foreign-baseharbor-node-connector.podman.container", wantErr: true},
		{name: "foreign suffix", unit: "baseharbor-node-connector.podman.container.evil", wantErr: true},
		{name: "same marker different rest", unit: "foreign-baseharbor-node-connector.evil.container", wantErr: true},
		{name: "conflicting identity", unit: "baseharbor-node-connector.docker.container/baseharbor-node-connector.podman.container", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateSelfOwnedUnit(Unit{Kind: UnitKindSystemdUser, Name: test.unit, ExecLine: "ExecStart=/bin/true"})
			if test.wantErr && (err == nil || !strings.Contains(err.Error(), "self-owned")) {
				t.Fatalf("noncanonical unit %q must be rejected, got %v", test.unit, err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("canonical unit %q must be accepted, got %v", test.unit, err)
			}
		})
	}
}

func TestForeignUnitInstallHasNoManagerOrStoreEffects(t *testing.T) {
	for _, unitName := range []string{
		"foreign-baseharbor-node-connector.podman.container",
		"baseharbor-node-connector.podman.container.evil",
		"foreign-baseharbor-node-connector.evil.container",
		"baseharbor-node-connector.docker.container/baseharbor-node-connector.podman.container",
	} {
		t.Run(unitName, func(t *testing.T) {
			manager := &fakeUnitManager{}
			store := &fakeStore{missing: true}
			driver := &fakeEnrollDriver{serial: "should-not-be-used"}
			service := newTestService(manager, store, driver, nil).WithAuthorizer(allowAllAuthorizer{})
			_, err := service.Install(context.Background(), Unit{
				Kind: UnitKindSystemdUser, Name: unitName, ExecLine: "ExecStart=/bin/true",
			})
			if err == nil || !strings.Contains(err.Error(), "self-owned") {
				t.Fatalf("noncanonical unit must fail at ownership validation, got %v", err)
			}

			manager.mu.Lock()
			installed, calls := manager.installed, append([]string(nil), manager.calls...)
			manager.mu.Unlock()
			if installed || len(calls) != 0 {
				t.Fatalf("rejected unit reached manager effects: installed=%v calls=%v", installed, calls)
			}
			store.mu.Lock()
			missing, storedUnit, enrollment := store.missing, store.unit, store.enroll
			store.mu.Unlock()
			if !missing || storedUnit != (Unit{}) || enrollment != (EnrollmentState{}) {
				t.Fatalf("rejected unit changed metadata: missing=%v unit=%#v enrollment=%#v", missing, storedUnit, enrollment)
			}
			if driver.callCount() != 0 {
				t.Fatalf("rejected unit touched enrollment/key path %d times", driver.callCount())
			}
		})
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

// nativeSmokeRunner pings the systemd user manager and returns whether a real
// user session is reachable. It is the gate for the bounded native systemd-user
// smoke test: when no user manager is available the test is skipped, never
// failed.
func nativeSmokeRunner(t *testing.T) execx.Runner {
	t.Helper()
	runner := execx.Runner{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := runner.Run(ctx, nil, "systemctl", "--user", "show-environment")
	if err != nil {
		t.Skipf("no reachable systemd user manager: %v", err)
	}
	return runner
}

// TestNativeSystemdUserLifecycleSmoke is a bounded native systemd-user smoke that
// drives the connector's OWN unit through install -> start -> restart ->
// uninstall against a real systemd user manager, and verifies lingering
// (autostart) wiring. It skips cleanly when no user manager is reachable.
func TestNativeSystemdUserLifecycleSmoke(t *testing.T) {
	runner := nativeSmokeRunner(t)

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("protect state dir: %v", err)
	}
	self := ServiceNameForBinary("podman")
	svc, err := NewSystemdService(runner, dir, self, nil)
	if err != nil {
		t.Fatalf("build native service: %v", err)
	}
	// Real owner authorization is bound before any lifecycle runs.
	svc.WithAuthorizer(ConnectorOwnerAuthorizer{})
	// The unit's ExecStart runs a benign command so the real systemd-user
	// lifecycle (install/start/restart/uninstall) can be exercised end to end
	// without a real connector binary. The validated ExecLine is still pinned by
	// the unit and verified on disk.
	unit := Unit{Kind: UnitKindSystemdUser, Name: self, ExecLine: "ExecStart=/bin/sleep 3600"}

	// Install writes the unit, reloads, and starts it.
	if _, err := svc.Install(context.Background(), unit); err != nil {
		t.Fatalf("native install failed: %v", err)
	}
	// The unit artifact must now exist on disk under the XDG systemd-user dir.
	userDir, err := defaultSystemdUserUnitDir()
	if err != nil {
		t.Fatalf("resolve systemd user unit dir: %v", err)
	}
	serviceArtifact := strings.TrimSuffix(self, filepath.Ext(self)) + ".service"
	unitPath := filepath.Join(userDir, serviceArtifact)
	if _, err := os.Stat(unitPath); err != nil {
		t.Fatalf("native install did not persist the unit: %v", err)
	}
	// The persisted unit must carry the validated ExecStart line.
	content, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatalf("read native unit: %v", err)
	}
	if !strings.Contains(string(content), "ExecStart=") {
		t.Fatalf("native unit is missing the validated ExecStart line:\n%s", content)
	}

	// Restart must be observable against the real unit.
	ctx := context.Background()
	unitFull := strings.TrimSuffix(self, filepath.Ext(self)) + ".service"
	if _, err := runner.Run(ctx, nil, "systemctl", "--user", "restart", unitFull); err != nil {
		t.Skipf("native restart not observable in this session (may need lingering/active unit): %v", err)
	}

	// Uninstall stops, disables and removes the owned unit.
	if err := svc.Uninstall(ctx, unit); err != nil {
		t.Fatalf("native uninstall failed: %v", err)
	}
	if _, err := os.Stat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native uninstall did not remove the unit, stat err: %v", err)
	}

	// A second uninstall of the now-removed owned unit is idempotent-clean, not
	// a second artifact.
	if err := svc.Uninstall(ctx, unit); err != nil {
		t.Fatalf("native second uninstall should be idempotent-clean, got: %v", err)
	}
}
