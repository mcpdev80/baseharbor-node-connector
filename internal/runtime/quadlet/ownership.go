package quadlet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

func (m *Manager) store() (*fssecure.Root, error) {
	// Kept outside generator search paths so retained immutable revisions never
	// become duplicate generated units.
	return fssecure.OpenRoot(m.baseDir + "-state")
}

func artifactID(name string, content []byte) string {
	nameSum, contentSum := sha256.Sum256([]byte(name)), sha256.Sum256(content)
	return hex.EncodeToString(nameSum[:8]) + "-" + hex.EncodeToString(contentSum[:16])
}

func (m *Manager) verifyOwned(name string) error {
	file, err := os.Open(filepath.Join(m.baseDir, name))
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := os.Lstat(filepath.Join(m.baseDir, name))
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("foreign Quadlet artifact")
	}
	data, err := io.ReadAll(io.LimitReader(file, 262145))
	if err != nil || len(data) > 262144 {
		return errors.New("invalid bounded Quadlet artifact")
	}
	store, err := m.store()
	if err != nil {
		return err
	}
	directory, err := store.PublishedBundleDirectory(artifactID(name, data))
	if err != nil {
		return errors.New("Quadlet artifact has no verified realization receipt")
	}
	owned, err := os.Lstat(filepath.Join(store.Path(), directory, name))
	if err != nil || !os.SameFile(info, owned) {
		return errors.New("foreign Quadlet artifact")
	}
	return nil
}

func (m *Manager) writeOwned(ctx context.Context, name string, content []byte) error {
	if len(content) == 0 || len(content) > 262144 {
		return errors.New("invalid bounded Quadlet content")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(m.baseDir, 0700); err != nil {
		return err
	}
	_, statErr := os.Lstat(filepath.Join(m.baseDir, name))
	if statErr == nil {
		if err := m.verifyOwned(name); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	store, err := m.store()
	if err != nil {
		return err
	}
	id := artifactID(name, content)
	directory, err := store.PublishBundle(ctx, id, []fssecure.BundleFile{{Path: name, Data: content, Mode: 0600}})
	if errors.Is(err, os.ErrExist) {
		directory, err = store.PublishedBundleDirectory(id)
	}
	if err != nil {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(m.baseDir))
	if err != nil {
		return err
	}
	defer parent.Close()
	destination := filepath.Join(filepath.Base(m.baseDir), name)
	if err := parent.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	source := filepath.Join(filepath.Base(store.Path()), directory, name)
	if errors.Is(statErr, os.ErrNotExist) {
		if err := parent.Link(source, destination); err != nil {
			return err
		}
	} else {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		temporary := filepath.Join(filepath.Dir(destination), ".baseharbor-"+hex.EncodeToString(nonce[:]))
		if err := parent.Link(source, temporary); err != nil {
			return err
		}
		defer parent.Remove(temporary)
		if err := parent.Rename(temporary, destination); err != nil {
			return err
		}
	}
	return m.verifyOwned(name)
}

func (m *Manager) setActivation(ctx context.Context, name string, active bool) error {
	content := "[Install]\nWantedBy=\nRequiredBy=\nUpheldBy=\nAlias=\n"
	if active {
		content += "WantedBy=default.target\n"
	}
	return m.writeOwned(ctx, filepath.Join(name+".d", "99-baseharbor-activation.conf"), []byte(content))
}
