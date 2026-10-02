package quadlet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
)

var allowedExtensions = map[string]struct{}{
	".build": {},
	".container": {},
	".image": {},
	".kube": {},
	".network": {},
	".pod": {},
	".volume": {},
}

type Entry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Unit    string `json:"unit"`
	Enabled string `json:"enabled"`
	Active  string `json:"active"`
}

type Manager struct {
	baseDir string
	runner  execx.Runner
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
	return &Manager{baseDir: abs, runner: execx.Runner{}}, nil
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
			Name: name,
			Path: filepath.Join(m.baseDir, name),
			Kind: strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), "."),
			Unit: unit,
			Enabled: m.state(ctx, "is-enabled", unit),
			Active: m.state(ctx, "is-active", unit),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (m *Manager) Apply(ctx context.Context, name, content string, enable bool) error {
	path, _, err := m.resolve(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.baseDir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(m.baseDir, ".baseharbor-quadlet-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if _, err := m.runner.Run(ctx, nil, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	if enable {
		_, err = m.runner.Run(ctx, nil, "systemctl", "--user", "enable", "--now", unitName(name))
		return err
	}
	return nil
}

func (m *Manager) Remove(ctx context.Context, name string) error {
	path, unit, err := m.resolve(name)
	if err != nil {
		return err
	}
	_, _ = m.runner.Run(ctx, nil, "systemctl", "--user", "disable", "--now", unit)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, err = m.runner.Run(ctx, nil, "systemctl", "--user", "daemon-reload")
	return err
}

func (m *Manager) Enable(ctx context.Context, name string) error {
	_, unit, err := m.resolve(name)
	if err != nil {
		return err
	}
	if _, err := m.runner.Run(ctx, nil, "systemctl", "--user", "daemon-reload"); err != nil {
		return err
	}
	_, err = m.runner.Run(ctx, nil, "systemctl", "--user", "enable", "--now", unit)
	return err
}

func (m *Manager) Disable(ctx context.Context, name string) error {
	_, unit, err := m.resolve(name)
	if err != nil {
		return err
	}
	_, err = m.runner.Run(ctx, nil, "systemctl", "--user", "disable", "--now", unit)
	return err
}

func (m *Manager) resolve(name string) (string, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.ContainsAny(name, "\x00\r\n") {
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
	return strings.TrimSuffix(name, filepath.Ext(name)) + ".service"
}
