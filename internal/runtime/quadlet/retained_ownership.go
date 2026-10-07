package quadlet

import (
	"errors"
	"os"
	"path/filepath"
)

// Ordinary removal retains immutable realization history outside generator
// search paths. Only the exact unchanged persistent-resource source can reuse
// it; an existing foreign unit cannot be replaced through this path. Native
// ownership labels are still independently checked by the caller.
func (m *Manager) verifyRetainedResource(name string, content []byte) error {
	if _, err := os.Lstat(filepath.Join(m.baseDir, name)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("retained ownership requires an absent active artifact")
	}
	if info, err := os.Lstat(m.baseDir + "-state"); err != nil || !info.IsDir() {
		return errors.New("retained realization history is missing")
	}
	store, err := m.store()
	if err != nil {
		return err
	}
	directory, err := store.PublishedBundleDirectory(artifactID(name, content))
	if err != nil {
		return err
	}
	return store.VerifyPublishedBundle(directory, filepath.Join(directory, name))
}
