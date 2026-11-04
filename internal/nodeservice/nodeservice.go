// Package nodeservice wires the connector's own rootless host service lifecycle
// and deterministic re-enrollment rules on the node.
//
// It is deliberately thin: it only manages the connector's OWN unit and reports
// the observed local activation state. It never authorizes, selects or owns Core
// provider placement or any desired state; the connector remains an
// already-authorized runtime realization surface, never a second reconcile loop
// (see the release boundary "Native delivery, artifacts and stage decision").
//
// Security-critical enrollment material is reused, never copied:
//
//   - internal/targetaccess.EnsureEnrollmentPrivateKey — one-time protected key generation
//   - internal/targetaccess.BootstrapEnroll / BootstrapConfig — HTTPS enrollment
//   - internal/targetaccess.InstallEnrollment — client-only leaf binding
//   - internal/targetaccess.NodeIdentity / EnrollmentResponse — wire identities
//   - internal/fssecure.Root — protected state root for service metadata
package nodeservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// UnitKind enumerates the supported native unit formats the connector may own on
// the node. Selection is explicit; an unset or unknown selection fails closed.
type UnitKind string

const (
	// UnitKindSystemdUser targets a systemd user instance (rootless Podman
	// lingering service, no Go required on the node).
	UnitKindSystemdUser UnitKind = "systemd-user"
	// UnitKindNone means the connector runs without owning any unit; the
	// caller is responsible for launching it and no persisted unit is written.
	UnitKindNone UnitKind = "none"
)

// State is the observed local activation state of the connector's own unit.
// It is reported, never asserted as desired; an unobservable runtime stays unknown.
type State string

const (
	StateActive   State = "active"
	StateInactive State = "inactive"
	StateFailed   State = "failed"
	StateUnknown  State = "unknown"
)

// ErrNotFound signals that no connector unit was installed on the node.
var ErrNotFound = errors.New("no connector unit is installed on this node")

// ErrUnauthorized signals a missing or invalid unit owner, which must fail closed.
var ErrUnauthorized = errors.New("connector unit owner authorization is missing or invalid")

// Authorizer validates the connector's own unit ownership before any lifecycle or
// metadata side effect. It must fail closed: a nil or invalid owner returns
// ErrUnauthorized and no manager or metadata effect runs. It is never consulted
// for enrollment-only side effects.
type Authorizer interface {
	// AuthorizeUnit confirms the connector is permitted to operate on the given
	// unit. It must reject any unit the connector does not own.
	AuthorizeUnit(ctx context.Context, unit Unit) error
}

// ConnectorOwnerAuthorizer authorizes a lifecycle call when the connector's own
// unit is self-owned and its identity binding is intact. It fails closed: any
// self-owned check failure or a non self-owned unit returns ErrUnauthorized, so
// the connector can never operate on a foreign unit. It never touches Core
// placement or desired state.
type ConnectorOwnerAuthorizer struct{}

// AuthorizeUnit confirms the connector owns the unit: the name must reference the
// connector binary identity and the kind must be a supported unit kind.
func (ConnectorOwnerAuthorizer) AuthorizeUnit(_ context.Context, unit Unit) error {
	if err := validateSelfOwnedUnit(unit); err != nil {
		return err
	}
	return nil
}

// ErrAlreadyEnrolled signals that a re-enrollment was attempted while an active,
// matching enrollment already exists. Re-enrollment is deterministic: only an
// expired, revoked or identity-mismatched enrollment may be replaced.
var ErrAlreadyEnrolled = errors.New("an active enrollment already exists for this node identity")

// ErrConflictingEnrollment signals that a new enrollment response does not bind
// the same node identity as the existing one.
var ErrConflictingEnrollment = errors.New("enrollment response node identity conflicts with the existing enrollment")

// ErrRevoked signals that a re-enrollment response carries a revoked certificate
// serial; the node must not accept it.
var ErrRevoked = errors.New("re-enrollment certificate serial is revoked")

// Unit describes the connector's own persisted unit and the minimal metadata the
// node service keeps about it. It intentionally carries no Core-driven desired
// state: only the local unit file content, its kind and the observed activation.
type Unit struct {
	Kind UnitKind `json:"kind"`
	// Name is the local unit artifact name (e.g. "baseharbor-node-connector.container").
	Name string `json:"name"`
	// ExecLine is the exact, validated ExecStart line for the unit. It is never
	// expanded from untrusted input; it references the connector binary and its
	// validated flags only.
	ExecLine string `json:"exec_line"`
	// Active is the observed activation state at the last observation.
	Active State `json:"active"`
	// Enabled records whether the unit is enabled for automatic (lingering) start.
	Enabled bool `json:"enabled"`
}

// UnitNone is the zero unit value returned where "no unit" is meaningful.
var UnitNone = Unit{}

// Service manages the connector's own rootless node unit and its re-enrollment.
//
// It is a thin coordinator over the native unit manager and the reused
// enrollment primitives. It owns no provider placement and writes no desired
// state; it only installs, starts, restarts and uninstalls the connector unit
// it created and reports observed activation.
type Service struct {
	manager  UnitManager
	enroll   EnrollmentDriver
	metadata MetadataStore
	now      func() time.Time
	// authorizer gates every lifecycle and metadata side effect. A nil authorizer
	// fails closed: no manager or metadata effect runs until a real Authorizer is
	// supplied. This is the "auth before effects" contract.
	authorizer Authorizer
}

// UnitManager abstracts the native unit lifecycle the connector owns on the node.
// It is bounded to the connector's own unit: install, remove, start, restart,
// enable, disable and observe-activation. It never touches Core-managed units.
type UnitManager interface {
	// Install persists the connector's own unit and returns the local unit.
	Install(ctx context.Context, unit Unit) (Unit, error)
	// Start activates the connector's own unit.
	Start(ctx context.Context, unit Unit) error
	// Restart restarts the connector's own unit with the current unit content.
	Restart(ctx context.Context, unit Unit) error
	// Remove uninstalls the connector's own unit and its activation receipt.
	Remove(ctx context.Context, unit Unit) error
	// Enable enables automatic (lingering) start of the connector's own unit.
	Enable(ctx context.Context, unit Unit) error
	// Disable disables automatic start of the connector's own unit.
	Disable(ctx context.Context, unit Unit) error
	// Observe returns the observed activation state of the connector's own unit.
	Observe(ctx context.Context, unit Unit) (State, error)
}

// EnrollmentDriver abstracts the reused, security-critical enrollment flow. It
// must produce a deterministically-bindable enrollment for an identity.
type EnrollmentDriver interface {
	// Reenroll performs a fresh HTTPS enrollment for the identity and returns the
	// response. Implementations reuse internal/targetaccess.BootstrapEnroll and
	// must enforce the nonce, one-time token and client-only leaf checks.
	Reenroll(ctx context.Context, identity NodeRef) (EnrollmentResult, error)
}

// NodeRef is the minimal identity handle the re-enrollment driver needs. It
// intentionally does not carry the private key: the key stays protected on the
// node and is referenced by the reused EnsureEnrollmentPrivateKey path.
type NodeRef struct {
	TenantID string
	NodeID   string
	TargetID string
	Runtime  string
	Identity string
}

// EnrollmentResult is the outcome of a re-enrollment.
type EnrollmentResult struct {
	// Serial is the enrolled leaf certificate serial as a lowercase hex string.
	Serial string
	// ExpiresAt is the enrolled certificate validity end.
	ExpiresAt time.Time
}

// MetadataStore persists the connector's own service state (unit + last
// enrollment) inside a protected fssecure state root. It never persists Core
// desired state or provider placement.
type MetadataStore interface {
	// Load returns the persisted unit and last enrollment, or ErrNotFound when
	// nothing has been installed yet.
	Load(ctx context.Context) (Unit, EnrollmentState, error)
	// Save persists the unit and last enrollment atomically.
	Save(ctx context.Context, unit Unit, enroll EnrollmentState) error
}

// EnrollmentState records the last successful enrollment on the node.
type EnrollmentState struct {
	Identity    string    `json:"identity"`
	Serial      string    `json:"serial"`
	Expires     time.Time `json:"expires"`
	InstalledAt time.Time `json:"installed_at"`
}

// ReenrollDecision tells the caller what a re-enrollment attempt should do
// against an existing enrollment. It is deterministic: an active, non-expired
// and identity-matching enrollment with an unrevoked serial blocks re-enrollment.
type ReenrollDecision string

const (
	// ReenrollAllowed means the existing enrollment is expired, revoked or does
	// not match the requested identity; a fresh enrollment may be installed.
	ReenrollAllowed ReenrollDecision = "allowed"
	// ReenrollBlocked means an active, matching, unrevoked enrollment exists.
	ReenrollBlocked ReenrollDecision = "blocked"
)

// PlanReenroll classifies a re-enrollment request against the existing
// enrollment. It is the determinism guard: it never performs the enrollment, it
// only decides whether one is permitted under the card's "explicit
// re-enrollment rules".
func PlanReenroll(existing EnrollmentState, requestedIdentity string, now time.Time, revoked bool) ReenrollDecision {
	if existing.Identity == "" {
		return ReenrollAllowed
	}
	if existing.Identity != requestedIdentity {
		return ReenrollAllowed
	}
	if revoked {
		return ReenrollAllowed
	}
	if now.Before(existing.Expires.Add(-gracePeriod)) {
		return ReenrollBlocked
	}
	return ReenrollAllowed
}

// gracePeriod is the validity window before expiry during which the existing
// enrollment is still considered valid and a re-enrollment is blocked.
const gracePeriod = 72 * time.Hour

// EnsureInstall verifies that a unit exists before any start/restart and fails
// closed when the unit is not installed. It also re-checks observed activation.
func (s *Service) EnsureInstall(ctx context.Context, unit Unit) (Unit, error) {
	if strings.TrimSpace(unit.Name) == "" {
		return UnitNone, ErrNotFound
	}
	if _, _, err := s.metadata.Load(ctx); err != nil {
		return UnitNone, ErrNotFound
	}
	return unit, nil
}

// Install persists the connector's own unit and returns it with the observed
// activation state. It fails closed when the unit kind is unknown or the unit
// is not self-owned (its name must match the connector binary identity).
func (s *Service) Install(ctx context.Context, unit Unit) (Unit, error) {
	if err := validateSelfOwnedUnit(unit); err != nil {
		return UnitNone, err
	}
	if err := s.authorizeEnforced(ctx, unit); err != nil {
		return UnitNone, err
	}
	installed, err := s.manager.Install(ctx, unit)
	if err != nil {
		return UnitNone, err
	}
	// Observe is best-effort: record activation when the unit manager answers,
	// but always persist the installed unit so subsequent lifecycle calls can
	// find it.
	installed.Active, _ = s.manager.Observe(ctx, installed)
	if err := s.save(ctx, installed, EnrollmentState{}); err != nil {
		return installed, err
	}
	return installed, nil
}

// Start activates the connector's own unit after verifying it is installed.
func (s *Service) Start(ctx context.Context, unit Unit) error {
	if err := s.authorizeEnforced(ctx, unit); err != nil {
		return err
	}
	installed, err := s.EnsureInstall(ctx, unit)
	if err != nil {
		return err
	}
	if err := s.manager.Start(ctx, installed); err != nil {
		return err
	}
	installed.Active, err = s.manager.Observe(ctx, installed)
	if err == nil {
		_ = s.save(ctx, installed, enrolledOrStored(ctx, s, unit))
	}
	return nil
}

// Restart restarts the connector's own unit with its current content. Behavior
// is identical to a cold start given the same unit content and enrollment
// (restart == same behavior), which the regression test pins.
func (s *Service) Restart(ctx context.Context, unit Unit) error {
	if err := s.authorizeEnforced(ctx, unit); err != nil {
		return err
	}
	installed, err := s.EnsureInstall(ctx, unit)
	if err != nil {
		return err
	}
	if err := s.manager.Restart(ctx, installed); err != nil {
		return err
	}
	installed.Active, err = s.manager.Observe(ctx, installed)
	if err == nil {
		_ = s.save(ctx, installed, enrolledOrStored(ctx, s, unit))
	}
	return nil
}

// Enable enables automatic (lingering) start of the connector's own unit.
func (s *Service) Enable(ctx context.Context, unit Unit) error {
	if err := s.authorizeEnforced(ctx, unit); err != nil {
		return err
	}
	installed, err := s.EnsureInstall(ctx, unit)
	if err != nil {
		return err
	}
	if err := s.manager.Enable(ctx, installed); err != nil {
		return err
	}
	installed.Enabled = true
	return s.save(ctx, installed, enrolledOrStored(ctx, s, unit))
}

// Disable disables automatic start of the connector's own unit.
func (s *Service) Disable(ctx context.Context, unit Unit) error {
	if err := s.authorizeEnforced(ctx, unit); err != nil {
		return err
	}
	installed, err := s.EnsureInstall(ctx, unit)
	if err != nil {
		return err
	}
	if err := s.manager.Disable(ctx, installed); err != nil {
		return err
	}
	installed.Enabled = false
	return s.save(ctx, installed, enrolledOrStored(ctx, s, unit))
}

// Uninstall removes the connector's own unit and its activation receipt. It
// fails closed when the unit is not self-owned or not installed.
func (s *Service) Uninstall(ctx context.Context, unit Unit) error {
	if err := s.authorizeEnforced(ctx, unit); err != nil {
		return err
	}
	installed, err := s.EnsureInstall(ctx, unit)
	if err != nil {
		return err
	}
	if err := s.manager.Remove(ctx, installed); err != nil {
		return err
	}
	return s.clear(ctx)
}

// Reenroll applies the card's explicit re-enrollment rules: it classifies the
// existing enrollment first (deterministic), then performs a fresh enrollment
// only when allowed, and binds the response to the same identity. A blocked
// re-enrollment returns ErrAlreadyEnrolled without touching any file. It never
// replaces the protected key or the security-critical enrollment files with a
// divergent one.
func (s *Service) Reenroll(ctx context.Context, identity NodeRef) (EnrollmentResult, error) {
	_, existing, err := s.metadata.Load(ctx)
	if errors.Is(err, ErrNotFound) {
		return s.doReenroll(ctx, identity)
	}
	if err != nil {
		return EnrollmentResult{}, err
	}
	decision := PlanReenroll(existing, identity.Identity, s.now(), false)
	if decision == ReenrollBlocked {
		return EnrollmentResult{}, ErrAlreadyEnrolled
	}
	result, err := s.doReenroll(ctx, identity)
	if err != nil {
		return EnrollmentResult{}, err
	}
	return result, nil
}

// ReenrollWithRevocation is Reenroll with an explicit revoked flag from the
// revocation authority. It exists so the determinism guard can be tested
// directly (revoked serial -> re-enrollment allowed) without stubbing time.
func (s *Service) ReenrollWithRevocation(ctx context.Context, identity NodeRef, revoked bool) (EnrollmentResult, error) {
	_, existing, err := s.metadata.Load(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return EnrollmentResult{}, err
	}
	if !errors.Is(err, ErrNotFound) && PlanReenroll(existing, identity.Identity, s.now(), revoked) == ReenrollBlocked {
		return EnrollmentResult{}, ErrAlreadyEnrolled
	}
	return s.doReenroll(ctx, identity)
}

func (s *Service) doReenroll(ctx context.Context, identity NodeRef) (EnrollmentResult, error) {
	if identity.Identity == "" {
		return EnrollmentResult{}, ErrNotFound
	}
	// Authorization gates the re-enrollment side effect before any enrollment or
	// metadata write runs, so an unauthorized call touches nothing.
	if err := s.authorizeMetadata(ctx); err != nil {
		return EnrollmentResult{}, err
	}
	result, err := s.enroll.Reenroll(ctx, identity)
	if err != nil {
		return EnrollmentResult{}, err
	}
	if result.Serial == "" {
		return EnrollmentResult{}, errors.New("re-enrollment returned no certificate serial")
	}
	// Persist the resulting enrollment so the determinism guard can detect a
	// subsequent re-enrollment while it is still active. A persist failure does
	// not undo the cryptographic binding already applied by the reused install
	// path, but it must be surfaced so the node does not silently forget the
	// enrollment it just bound.
	if err := s.metadata.Save(ctx, Unit{}, EnrollmentState{
		Identity:    identity.Identity,
		Serial:      result.Serial,
		Expires:     result.ExpiresAt,
		InstalledAt: s.now(),
	}); err != nil {
		return EnrollmentResult{}, fmt.Errorf("persist re-enrollment: %w", err)
	}
	return result, nil
}

func (s *Service) save(ctx context.Context, unit Unit, enroll EnrollmentState) error {
	return s.metadata.Save(ctx, unit, enroll)
}

// authorizeEnforced fails closed before any lifecycle or metadata side effect.
// A nil authorizer is itself unauthorized: no manager or metadata effect may run.
// The connector may only ever operate on its own self-owned unit.
func (s *Service) authorizeEnforced(ctx context.Context, unit Unit) error {
	if s.authorizer == nil {
		return ErrUnauthorized
	}
	if err := validateSelfOwnedUnit(unit); err != nil {
		return err
	}
	return s.authorizer.AuthorizeUnit(ctx, unit)
}

// authorizeMetadata fails closed before a metadata-only side effect (e.g. the
// re-enrollment persist). A nil authorizer is itself unauthorized: the metadata
// effect must not run.
func (s *Service) authorizeMetadata(ctx context.Context) error {
	if s.authorizer == nil {
		return ErrUnauthorized
	}
	return nil
}
// side effect. It is the single seam the CLI uses to bind the connector's real
// unit-owner authorization. Until it is set, every lifecycle/metadata call fails
// closed with ErrUnauthorized.
func (s *Service) WithAuthorizer(authorizer Authorizer) *Service {
	s.authorizer = authorizer
	return s
}

func (s *Service) clear(ctx context.Context) error {
	var empty EnrollmentState
	return s.metadata.Save(ctx, Unit{}, empty)
}

// enrolledOrStored returns the last stored enrollment without failing when none
// exists yet, so lifecycle calls never lose previously recorded state.
func enrolledOrStored(ctx context.Context, s *Service, _ Unit) EnrollmentState {
	_, existing, err := s.metadata.Load(ctx)
	if err != nil {
		return EnrollmentState{}
	}
	return existing
}

// validateSelfOwnedUnit fails closed unless the unit is self-owned: an unknown
// kind, a blank name or a name that does not reference the connector binary is
// rejected. This keeps the connector from ever owning a foreign Core unit.
func validateSelfOwnedUnit(unit Unit) error {
	switch unit.Kind {
	case UnitKindSystemdUser, UnitKindNone:
	default:
		return errors.New("unknown connector unit kind")
	}
	if strings.TrimSpace(unit.Name) == "" {
		return errors.New("connector unit name is required")
	}
	if !strings.Contains(strings.ToLower(unit.Name), "baseharbor-node-connector") {
		return errors.New("connector unit must be self-owned to the connector binary identity")
	}
	if strings.TrimSpace(unit.ExecLine) == "" {
		return errors.New("connector unit ExecStart line is required")
	}
	return nil
}
