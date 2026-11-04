// Package nodeservice wires the connector's own rootless host service lifecycle
// and deterministic re-enrollment rules on the node.
package nodeservice

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
)

// systemdUnitManager implements UnitManager for a rootless systemd user
// instance. It owns only the connector's own unit and observes activation; it
// never applies or removes Core-managed units.
//
// The real native wiring shells out to `systemctl --user` / `podman` against a
// reachable systemd user manager. That harness is intentionally injected here as
// the execx.Runner so the determinism rules above can be tested without a live
// session. A missing user manager is reported as unreachable, not swallowed.
type systemdUnitManager struct {
	runner execx.Runner
	// selfName is the exact unit artifact basename the connector owns.
	selfName string
}

func newSystemdUnitManager(runner execx.Runner, selfName string) *systemdUnitManager {
	return &systemdUnitManager{runner: runner, selfName: selfName}
}

func (m *systemdUnitManager) availableOr(ctx context.Context) bool {
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := m.runner.Run(probe, nil, "systemctl", "--user", "show-environment")
	return err == nil
}

func (m *systemdUnitManager) Install(_ context.Context, unit Unit) (Unit, error) {
	if !m.availableOr(context.Background()) {
		return UnitNone, errors.New("systemd user manager is not reachable")
	}
	if unit.Name == "" {
		unit.Name = m.selfName
	}
	return unit, nil
}

func (m *systemdUnitManager) Start(ctx context.Context, unit Unit) error {
	return m.run(ctx, "start", unitName(unit))
}

func (m *systemdUnitManager) Restart(ctx context.Context, unit Unit) error {
	return m.run(ctx, "restart", unitName(unit))
}

func (m *systemdUnitManager) Remove(ctx context.Context, unit Unit) error {
	return m.run(ctx, "remove", unitName(unit))
}

func (m *systemdUnitManager) Enable(ctx context.Context, unit Unit) error {
	return m.run(ctx, "enable", unitName(unit))
}

func (m *systemdUnitManager) Disable(ctx context.Context, unit Unit) error {
	return m.run(ctx, "disable", unitName(unit))
}

func (m *systemdUnitManager) Observe(_ context.Context, unit Unit) (State, error) {
	out, err := m.runner.Run(context.Background(), nil, "systemctl", "--user", "is-active", unitName(unit))
	if err != nil {
		return StateUnknown, nil
	}
	switch strings.TrimSpace(out.Stdout) {
	case "active":
		return StateActive, nil
	case "inactive":
		return StateInactive, nil
	case "failed":
		return StateFailed, nil
	default:
		return StateUnknown, nil
	}
}

func (m *systemdUnitManager) run(ctx context.Context, op, unit string) error {
	if !m.availableOr(ctx) {
		return errors.New("systemd user manager is not reachable")
	}
	_, err := m.runner.Run(ctx, nil, "systemctl", "--user", op, unit)
	return err
}

// unitName maps the connector's unit artifact basename to its systemd unit.
// A .container artifact becomes baseharbor-node-connector.service.
func unitName(unit Unit) string {
	base := unit.Name
	if ext := filepath.Ext(base); ext != "" {
		base = strings.TrimSuffix(base, ext)
	}
	return base + ".service"
}

// protectedStateStore persists the connector's own service state in a single
// protected file with 0600 permissions, a NUL-free name and an integrity tag.
// It never writes Core desired state or provider placement.
type protectedStateStore struct {
	path string
	mu   sync.Mutex
}

func newProtectedStateStore(dir string) (*protectedStateStore, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve service state directory: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create service state directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve service state directory: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("service state directory must be a protected directory")
	}
	return &protectedStateStore{path: filepath.Join(resolved, "service.state.json")}, nil
}

func (s *protectedStateStore) Load(_ context.Context) (Unit, EnrollmentState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Unit{}, EnrollmentState{}, ErrNotFound
	}
	if err != nil {
		return Unit{}, EnrollmentState{}, fmt.Errorf("read connector service state: %w", err)
	}
	if err := verifyStateTag(data); err != nil {
		return Unit{}, EnrollmentState{}, err
	}
	var state struct {
		Unit   Unit            `json:"unit"`
		Enroll EnrollmentState `json:"enrollment"`
	}
	if err := json.Unmarshal(stripStateTag(data), &state); err != nil {
		return Unit{}, EnrollmentState{}, fmt.Errorf("parse connector service state: %w", err)
	}
	return state.Unit, state.Enroll, nil
}

func (s *protectedStateStore) Save(_ context.Context, unit Unit, enroll EnrollmentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := json.MarshalIndent(struct {
		Unit   Unit            `json:"unit"`
		Enroll EnrollmentState `json:"enrollment"`
	}{unit, enroll}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode connector service state: %w", err)
	}
	tagged := append(appendStateTag(payload), '\n')
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, tagged, 0o600); err != nil {
		return fmt.Errorf("write connector service state: %w", err)
	}
	return os.Rename(tmp, s.path)
}

func (s *protectedStateStore) clear(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear connector service state: %w", err)
	}
	return nil
}

const stateTagPrefix = "#baseharbor-nodeservice-state/v1\n"

func appendStateTag(payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return append([]byte(stateTagPrefix), digest[:]...)
}

func verifyStateTag(data []byte) error {
	if !strings.HasPrefix(string(data), stateTagPrefix) {
		return errors.New("connector service state is missing its integrity tag")
	}
	lines := strings.SplitN(string(data), "\n", 3)
	if len(lines) < 3 {
		return errors.New("connector service state has a malformed integrity tag")
	}
	payload := []byte(lines[1])
	recorded := []byte(strings.TrimSpace(lines[2]))
	if len(recorded) != 32 {
		return errors.New("connector service state integrity tag has wrong length")
	}
	want := sha256.Sum256(payload)
	for i := range want {
		if want[i] != recorded[i] {
			return errors.New("connector service state integrity tag does not match payload")
		}
	}
	return nil
}

func stripStateTag(data []byte) []byte {
	idx := strings.IndexByte(string(data), '\n')
	if idx < 0 {
		return data
	}
	return data[idx+1:]
}

// NewService constructs the thin service coordinator over a native unit manager
// and a protected metadata store. The enrollment driver is injected so the
// security-critical bootstrap path stays the single source of enrollment truth.
func NewService(manager UnitManager, store MetadataStore, enroll EnrollmentDriver, now func() time.Time) *Service {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{manager: manager, enroll: enroll, metadata: store, now: now}
}

// NewSystemdService wires a rootless systemd-user service manager over a
// protected state root and a bootstrap re-enrollment driver.
func NewSystemdService(
	runner execx.Runner,
	stateDir string,
	selfName string,
	driver EnrollmentDriver,
) (*Service, error) {
	if selfName == "" {
		return nil, errors.New("connector self unit name is required")
	}
	store, err := newProtectedStateStore(stateDir)
	if err != nil {
		return nil, err
	}
	manager := newSystemdUnitManager(runner, selfName)
	return NewService(manager, store, driver, nil), nil
}

// ServiceNameForBinary returns the canonical connector unit artifact basename
// for an optional runtime tag, e.g. baseharbor-node-connector.podman.container.
func ServiceNameForBinary(tag string) string {
	base := "baseharbor-node-connector"
	if strings.TrimSpace(tag) != "" {
		base = base + "." + tag
	}
	return base + ".container"
}

// trimPemTail trims trailing whitespace from decoded PEM bytes.
func trimPemTail(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}

// x509ParseCertificate parses a DER certificate.
func x509ParseCertificate(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

// enrollmentSerial parses the enrolled leaf certificate serial as a lowercase
// hex string. It reuses only the standard PEM/x509 parse of the enrollment
// response rather than re-implementing the security-critical binding.
func enrollmentSerial(pemText string) (string, error) {
	block, rest := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("enrollment response contains no certificate")
	}
	if trimmed := trimPemTail(rest); len(trimmed) != 0 {
		return "", errors.New("enrollment response certificate contains trailing material")
	}
	cert, err := x509ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse enrolled certificate: %w", err)
	}
	return cert.SerialNumber.Text(16), nil
}
