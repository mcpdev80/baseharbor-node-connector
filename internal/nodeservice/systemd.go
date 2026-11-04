// Package nodeservice wires the connector's own rootless host service lifecycle
// and deterministic re-enrollment rules on the node.
package nodeservice

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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
// instance. It writes, activates and removes ONLY the connector's own unit and
// observes its activation. It never applies or removes Core-managed units: every
// operation is scoped to the connector's own unit artifact basename.
//
// The real native wiring shells out to `systemctl --user` / `podman` against a
// reachable systemd user manager. That harness is intentionally injected here as
// the execx.Runner so the determinism rules above can be tested without a live
// session. A missing user manager is reported as unreachable, not swallowed.
type systemdUnitManager struct {
	runner execx.Runner
	// unitDir is the XDG systemd-user directory the unit artifact is written to.
	unitDir string
	// selfName is the exact unit artifact basename (e.g.
	// baseharbor-node-connector.podman.container) the connector owns.
	selfName string
}

func newSystemdUnitManager(runner execx.Runner, selfName, unitDir string) *systemdUnitManager {
	return &systemdUnitManager{runner: runner, unitDir: unitDir, selfName: selfName}
}

func (m *systemdUnitManager) availableOr(ctx context.Context) bool {
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := m.runner.Run(probe, nil, "systemctl", "--user", "show-environment")
	return err == nil
}

// artifactPath resolves the XDG systemd-user directory for the connector's OWN
// .service artifact. The .container quadlet basename is translated to its
// derived .service artifact so `systemctl --user` loads it directly without
// quadlet processing. Ownership stays on the connector's own artifact.
func (m *systemdUnitManager) artifactPath(unit Unit) (string, error) {
	if strings.TrimSpace(m.unitDir) == "" {
		return "", errors.New("systemd user unit directory is required")
	}
	created := false
	resolved, err := filepath.EvalSymlinks(m.unitDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("resolve systemd user unit directory: %w", err)
		}
		if err := os.MkdirAll(m.unitDir, 0o700); err != nil {
			return "", fmt.Errorf("create systemd user unit directory: %w", err)
		}
		created = true
		resolved = m.unitDir
	}
	if !created {
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			return "", fmt.Errorf("systemd user unit directory must be a directory: %w", err)
		}
	}
	name := unit.Name
	if strings.TrimSpace(name) == "" {
		name = m.selfName
	}
	if !strings.Contains(strings.ToLower(name), "baseharbor-node-connector") {
		return "", errors.New("connector unit must be self-owned to the connector binary identity")
	}
	// Translate the quadlet basename (baseharbor-node-connector.podman.container)
	// to the derived systemd .service artifact the manager owns.
	serviceName := serviceNameToService(name)
	abs, err := filepath.Abs(filepath.Join(resolved, serviceName))
	if err != nil {
		return "", fmt.Errorf("resolve systemd user unit path: %w", err)
	}
	if rel, err := filepath.Rel(resolved, abs); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("systemd user unit path escapes the unit directory")
	}
	return abs, nil
}

// serviceNameToService maps a quadlet artifact basename to its derived systemd
// .service artifact. Only the terminal quadlet extension is stripped, matching
// systemd-quadlet's own derivation: baseharbor-node-connector.podman.container
// -> baseharbor-node-connector.podman.service.
func serviceNameToService(name string) string {
	ext := filepath.Ext(name)
	if ext != "" {
		return strings.TrimSuffix(name, ext) + ".service"
	}
	return name + ".service"
}

// Install writes the connector's own unit with the validated ExecLine to the XDG
// systemd-user directory, reloads the manager, and starts it. Install reports
// failure when only the manager was probed and no unit was actually written: a
// real, persisted, activation-capable unit is the effect, not a probe.
func (m *systemdUnitManager) Install(ctx context.Context, unit Unit) (Unit, error) {
	if !m.availableOr(ctx) {
		return UnitNone, errors.New("systemd user manager is not reachable")
	}
	if strings.TrimSpace(unit.Name) == "" {
		unit.Name = m.selfName
	}
	if err := validateSelfOwnedUnit(unit); err != nil {
		return UnitNone, err
	}
	path, err := m.artifactPath(unit)
	if err != nil {
		return UnitNone, err
	}
	content, err := m.renderUnit(unit, path)
	if err != nil {
		return UnitNone, err
	}
	if err := atomicWriteUnit(path, content); err != nil {
		return UnitNone, err
	}
	if err := m.reload(ctx); err != nil {
		return UnitNone, err
	}
	if err := m.start(ctx, unit); err != nil {
		return UnitNone, err
	}
	return unit, nil
}

// renderUnit builds the .service file content for the connector's own unit. The
// validated ExecStart line (Unit.ExecLine, already "ExecStart=...") is emitted
// verbatim under [Service] so the unit never references untrusted input. The
// [Install] WantedBy directive requests lingering autostart across the user
// session.
func (m *systemdUnitManager) renderUnit(unit Unit, path string) (string, error) {
	var sb strings.Builder
	sb.WriteString("[Unit]\n")
	sb.WriteString("Description=BaseHarbor Connector node service\n\n")
	sb.WriteString("[Service]\n")
	sb.WriteString(unit.ExecLine + "\n")
	sb.WriteString("Restart=on-failure\n\n")
	sb.WriteString("[Install]\n")
	sb.WriteString("WantedBy=default.target\n")
	return sb.String(), nil
}

// Remove stops, disables and removes the connector's OWN unit through supported
// systemctl operations. It fails closed when the unit is not owned by the
// connector and never touches a foreign unit.
func (m *systemdUnitManager) Remove(ctx context.Context, unit Unit) error {
	if !m.availableOr(ctx) {
		return errors.New("systemd user manager is not reachable")
	}
	if strings.TrimSpace(unit.Name) == "" {
		unit.Name = m.selfName
	}
	if err := validateSelfOwnedUnit(unit); err != nil {
		return err
	}
	path, err := m.artifactPath(unit)
	if err != nil {
		return err
	}
	// Stop and disable before removal so no activation receipt survives us. A unit
	// that is already gone is in the desired (removed) state, so a missing-unit
	// disable/stop is idempotent-clean, not an error.
	if err := m.disable(ctx, unit); err != nil {
		if !isUnitNotFound(err) {
			return err
		}
	}
	if err := m.stop(ctx, unit); err != nil {
		if !isUnitNotFound(err) {
			return err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove connector unit file: %w", err)
	}
	return m.reload(ctx)
}

// isUnitNotFound reports whether a systemctl error indicates the target unit
// does not exist (already removed), which uninstall treats as idempotent-clean.
func isUnitNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "no such unit") ||
		strings.Contains(msg, "not loaded")
}

func (m *systemdUnitManager) Start(ctx context.Context, unit Unit) error {
	return m.start(ctx, unit)
}

func (m *systemdUnitManager) Restart(ctx context.Context, unit Unit) error {
	if !m.availableOr(ctx) {
		return errors.New("systemd user manager is not reachable")
	}
	if strings.TrimSpace(unit.Name) == "" {
		unit.Name = m.selfName
	}
	return m.restart(ctx, unit)
}

func (m *systemdUnitManager) Enable(ctx context.Context, unit Unit) error {
	return m.enable(ctx, unit)
}

func (m *systemdUnitManager) Disable(ctx context.Context, unit Unit) error {
	return m.disable(ctx, unit)
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

func (m *systemdUnitManager) reload(ctx context.Context) error {
	if !m.availableOr(ctx) {
		return errors.New("systemd user manager is not reachable")
	}
	_, err := m.runner.Run(ctx, nil, "systemctl", "--user", "daemon-reload")
	return err
}

func (m *systemdUnitManager) start(ctx context.Context, unit Unit) error {
	if !m.availableOr(ctx) {
		return errors.New("systemd user manager is not reachable")
	}
	_, err := m.runner.Run(ctx, nil, "systemctl", "--user", "start", unitName(unit))
	return err
}

func (m *systemdUnitManager) restart(ctx context.Context, unit Unit) error {
	_, err := m.runner.Run(ctx, nil, "systemctl", "--user", "restart", unitName(unit))
	return err
}

func (m *systemdUnitManager) enable(ctx context.Context, unit Unit) error {
	if !m.availableOr(ctx) {
		return errors.New("systemd user manager is not reachable")
	}
	_, err := m.runner.Run(ctx, nil, "systemctl", "--user", "enable", unitName(unit))
	return err
}

func (m *systemdUnitManager) disable(ctx context.Context, unit Unit) error {
	if !m.availableOr(ctx) {
		return errors.New("systemd user manager is not reachable")
	}
	_, err := m.runner.Run(ctx, nil, "systemctl", "--user", "disable", unitName(unit))
	return err
}

func (m *systemdUnitManager) stop(ctx context.Context, unit Unit) error {
	_, err := m.runner.Run(ctx, nil, "systemctl", "--user", "stop", unitName(unit))
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
	// Layout: [payload][stateTagPrefix][hex-digest]. The prefix ends in "\n" so
	// the digest is always the trailing line; the payload's own newlines do not
	// fragment the tag.
	payloadDigest := sha256.Sum256(payload)
	tagged := append(payload, []byte(stateTagPrefix+hex.EncodeToString(payloadDigest[:]))...)
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

func verifyStateTag(data []byte) error {
	idx := strings.Index(string(data), stateTagPrefix)
	if idx < 0 {
		return errors.New("connector service state is missing its integrity tag")
	}
	payload := data[:idx]
	recorded := strings.TrimSpace(string(data[idx+len(stateTagPrefix):]))
	if len(recorded) != 64 {
		return errors.New("connector service state integrity tag has wrong length")
	}
	digest := sha256.Sum256(payload)
	want := hex.EncodeToString(digest[:])
	if !secureConstantTimeEqual(want, recorded) {
		return errors.New("connector service state integrity tag does not match payload")
	}
	return nil
}

func secureConstantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func stripStateTag(data []byte) []byte {
	idx := strings.Index(string(data), stateTagPrefix)
	if idx < 0 {
		return data
	}
	return data[:idx]
}

// atomicWriteUnit writes a unit artifact to the systemd-user directory with a
// 0600 regular file and no symlink escape: the unit must be persisted on disk
// before systemd can load, start or remove it.
func atomicWriteUnit(path string, content string) error {
	path = filepath.Clean(path)
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		return errors.New("unit directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create systemd user unit directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".baseharbor-unit-*")
	if err != nil {
		return fmt.Errorf("stage connector unit: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect connector unit permissions: %w", err)
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write connector unit: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("flush connector unit: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close connector unit: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install connector unit: %w", err)
	}
	return nil
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
// protected state root and a bootstrap re-enrollment driver. The unit artifact
// is written to the XDG systemd-user unit directory so `systemctl --user`
// observes, starts and removes the connector's own unit.
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
	// XDG systemd-user unit directory: the place `systemctl --user` loads units
	// from without quadlet processing.
	unitDir, err := defaultSystemdUserUnitDir()
	if err != nil {
		return nil, err
	}
	manager := newSystemdUnitManager(runner, selfName, unitDir)
	return NewService(manager, store, driver, nil), nil
}

// defaultSystemdUserUnitDir resolves the XDG systemd-user unit directory,
// defaulting to ~/.config/systemd/user and honoring XDG_CONFIG_HOME.
func defaultSystemdUserUnitDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); dir != "" {
		return filepath.Join(dir, "systemd", "user"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	if home == "" {
		return "", errors.New("systemd user unit directory is required")
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
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
