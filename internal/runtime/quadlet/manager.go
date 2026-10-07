package quadlet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
)

var allowedExtensions = map[string]struct{}{
	".build":     {},
	".container": {},
	".image":     {},
	".network":   {},
	".pod":       {},
	".volume":    {},
}

var artifactNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.(container|network|volume|pod|image|build)$`)

type Entry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Unit    string `json:"unit"`
	Enabled string `json:"enabled"`
	Active  string `json:"active"`
}

type Manager struct {
	baseDir    string
	runner     execx.Runner
	operations chan struct{}
}

func NewManager(baseDir string) (*Manager, error) {
	if strings.TrimSpace(baseDir) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		baseDir = filepath.Join(home, ".config", "containers", "systemd")
	}
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	return &Manager{baseDir: abs, runner: execx.Runner{}, operations: make(chan struct{}, 1)}, nil
}

func (m *Manager) Available(ctx context.Context) bool {
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := m.runner.Run(probe, nil, "systemctl", "--user", "show-environment")
	return err == nil
}

func (m *Manager) List(ctx context.Context) ([]Entry, error) {
	entries, err := os.ReadDir(m.baseDir)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, ok := allowedExtensions[strings.ToLower(filepath.Ext(name))]; !ok {
			continue
		}
		unit := unitName(name)
		result = append(result, Entry{
			Name:    name,
			Path:    filepath.Join(m.baseDir, name),
			Kind:    strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), "."),
			Unit:    unit,
			Enabled: m.state(ctx, "is-enabled", unit),
			Active:  m.state(ctx, "is-active", unit),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (m *Manager) acquire(ctx context.Context) (func(), error) {
	select {
	case m.operations <- struct{}{}:
		return func() { <-m.operations }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *Manager) Apply(ctx context.Context, name, content string, enable bool) error {
	_, unit, err := m.resolve(name)
	if err != nil {
		return err
	}
	release, err := m.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	return m.applyOwned(ctx, name, unit, content, enable)
}

func (m *Manager) applyOwned(ctx context.Context, name, unit, content string, enable bool) error {
	if err := m.writeOwned(ctx, name, []byte(content)); err != nil {
		return err
	}
	if err := m.setActivation(ctx, name, enable); err != nil {
		return err
	}
	if _, err := m.runner.Run(ctx, nil, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if enable {
		_, err := m.runner.Run(ctx, nil, "systemctl", "--user", "restart", unit)
		return err
	}
	return nil
}

func (m *Manager) Remove(ctx context.Context, name string) error {
	path, unit, err := m.resolve(name)
	if err != nil {
		return err
	}
	release, err := m.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := m.verifyOwned(name); err != nil {
		return err
	}
	activation := filepath.Join(name+".d", "99-baseharbor-activation.conf")
	if err := m.verifyOwned(activation); err != nil {
		return err
	}
	executionReceipt := executionBindingName(name)
	_, executionErr := os.Lstat(filepath.Join(m.baseDir, executionReceipt))
	if executionErr == nil {
		if err := m.verifyOwned(executionReceipt); err != nil {
			return err
		}
	} else if !errors.Is(executionErr, os.ErrNotExist) {
		return executionErr
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Managed project units have both protected realization receipts and
	// explicit native ownership labels. Recheck the latter before stopping:
	// an old unit receipt cannot authorize a subsequently replaced resource.
	if strings.Contains(string(content), "Label=com.docker.compose.project=") {
		if err := m.checkPublishedNativeOwnership(ctx, name, string(content)); err != nil {
			return err
		}
	}
	if _, err := m.runner.Run(ctx, nil, "systemctl", "--user", "stop", unit); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(m.baseDir, activation)); err != nil {
		return err
	}
	if executionErr == nil {
		if err := os.Remove(filepath.Join(m.baseDir, executionReceipt)); err != nil {
			return err
		}
	}
	_, err = m.runner.Run(ctx, nil, "systemctl", "--user", "daemon-reload")
	return err
}

func (m *Manager) Enable(ctx context.Context, name string) error { return m.activate(ctx, name, true) }
func (m *Manager) Disable(ctx context.Context, name string) error {
	return m.activate(ctx, name, false)
}

func (m *Manager) activate(ctx context.Context, name string, active bool) error {
	_, unit, err := m.resolve(name)
	if err != nil {
		return err
	}
	release, err := m.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := m.verifyOwned(name); err != nil {
		return err
	}
	if err := m.setActivation(ctx, name, active); err != nil {
		return err
	}
	if _, err := m.runner.Run(ctx, nil, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	operation := "stop"
	if active {
		operation = "start"
	}
	_, err = m.runner.Run(ctx, nil, "systemctl", "--user", operation, unit)
	return err
}

func (m *Manager) resolve(name string) (string, string, error) {
	name = strings.TrimSpace(name)
	if !artifactNamePattern.MatchString(name) {
		return "", "", fmt.Errorf("invalid quadlet name")
	}
	ext := strings.ToLower(filepath.Ext(name))
	if _, ok := allowedExtensions[ext]; !ok {
		return "", "", fmt.Errorf("unsupported quadlet extension")
	}
	return filepath.Join(m.baseDir, name), unitName(name), nil
}

func (m *Manager) state(ctx context.Context, action, unit string) string {
	result, err := m.runner.Run(ctx, nil, "systemctl", "--user", action, unit)
	if err != nil || strings.TrimSpace(result.Stdout) == "" {
		return "unknown"
	}
	return strings.TrimSpace(result.Stdout)
}

func unitName(name string) string {
	base, extension := strings.TrimSuffix(name, filepath.Ext(name)), filepath.Ext(name)
	if extension != ".container" {
		base += "-" + strings.TrimPrefix(extension, ".")
	}
	return base + ".service"
}
