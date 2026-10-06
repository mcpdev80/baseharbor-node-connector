package fssecure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Root confines connector-managed staged deployment artifacts to one directory.
type Root struct {
	path string
}

func OpenRoot(path string) (*Root, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("staging root is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create staging root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve staging root: %w", err)
	}
	return &Root{path: resolved}, nil
}

func (r *Root) Path() string {
	return r.path
}

// Existing resolves an existing path and rejects traversal/symlink escapes.
func (r *Root) Existing(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("path is required")
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(r.path, candidate)
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve staged path: %w", err)
	}
	if !within(r.path, resolved) {
		return "", fmt.Errorf("path escapes staging root")
	}
	return resolved, nil
}

func within(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func cleanRelative(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("path is required")
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("absolute staged path is not allowed")
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes staging root")
	}
	if strings.ContainsRune(clean, '\x00') {
		return "", fmt.Errorf("path contains NUL")
	}
	return clean, nil
}
