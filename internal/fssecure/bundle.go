package fssecure

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type BundleFile struct {
	Path string
	Data []byte
	Mode os.FileMode
}

type bundleManifest struct {
	Version   int               `json:"version"`
	ID        string            `json:"id"`
	Directory string            `json:"directory"`
	Files     map[string]string `json:"files"`
}

// PublishBundle commits a complete immutable object using a no-replace hard
// link. Uncommitted objects cannot be consumed. No existing bundle is replaced,
// including when separate processes race to publish the same identifier.
func (r *Root) PublishBundle(ctx context.Context, id string, files []BundleFile) (string, error) {
	if err := validBundleID(id); err != nil {
		return "", err
	}
	if len(files) == 0 || len(files) > 128 {
		return "", errors.New("invalid bundle file count")
	}
	manifest := bundleManifest{Version: 1, ID: id, Files: make(map[string]string)}
	total := 0
	for _, file := range files {
		clean, err := cleanRelative(file.Path)
		if err != nil || clean != file.Path || clean == ".manifest.json" {
			return "", errors.New("invalid bundle file path")
		}
		if _, duplicate := manifest.Files[clean]; duplicate {
			return "", errors.New("duplicate bundle file")
		}
		total += len(file.Data)
		if total > 4<<20 {
			return "", errors.New("bundle exceeds byte limit")
		}
		sum := sha256.Sum256(file.Data)
		manifest.Files[clean] = hex.EncodeToString(sum[:])
	}
	root, err := os.OpenRoot(r.path)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := root.MkdirAll("bundles", 0o700); err != nil {
		return "", err
	}
	info, err := root.Lstat("bundles")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("invalid bundle storage directory")
	}
	storage, err := root.OpenRoot("bundles")
	if err != nil {
		return "", err
	}
	defer storage.Close()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	objectName := ".object-" + hex.EncodeToString(nonce[:])
	manifest.Directory = filepath.Join("bundles", objectName)
	if err := storage.Mkdir(objectName, 0o700); err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = storage.RemoveAll(objectName)
		}
	}()
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		name := filepath.Join(objectName, file.Path)
		if err := storage.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			return "", err
		}
		mode := file.Mode & 0o700
		if mode == 0 {
			mode = 0o600
		}
		if err := writeNewBundleFile(storage, name, file.Data, mode); err != nil {
			return "", err
		}
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	name := filepath.Join(objectName, ".manifest.json")
	if err := writeNewBundleFile(storage, name, data, 0o600); err != nil {
		return "", err
	}
	if err := syncBundleDirectories(storage, objectName, files); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// Link fails if any file, directory or symlink already owns this name.
	if err := storage.Link(name, id+".json"); err != nil {
		return "", fmt.Errorf("publish immutable bundle: %w", err)
	}
	committed = true
	dir, err := storage.Open(".")
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return "", err
	}
	return manifest.Directory, nil
}

func writeNewBundleFile(root *os.Root, name string, data []byte, mode os.FileMode) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func syncBundleDirectories(root *os.Root, objectName string, files []BundleFile) error {
	directories := map[string]bool{objectName: true}
	for _, file := range files {
		for directory := filepath.Dir(filepath.Join(objectName, file.Path)); directory != "."; directory = filepath.Dir(directory) {
			directories[directory] = true
		}
	}
	for directory := range directories {
		file, err := root.Open(directory)
		if err != nil {
			return err
		}
		err = file.Sync()
		_ = file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func readBundleManifest(root *os.Root, name string) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return nil, errors.New("invalid bounded bundle manifest")
	}
	return data, nil
}

func (r *Root) PublishedBundleDirectory(id string) (string, error) {
	if err := validBundleID(id); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(r.path)
	if err != nil {
		return "", err
	}
	defer root.Close()
	data, err := readBundleManifest(root, filepath.Join("bundles", id+".json"))
	if err != nil {
		return "", err
	}
	var manifest bundleManifest
	if json.Unmarshal(data, &manifest) != nil || manifest.ID != id {
		return "", errors.New("invalid published bundle")
	}
	if err := r.VerifyPublishedBundle(manifest.Directory); err != nil {
		return "", err
	}
	return manifest.Directory, nil
}

var bundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func validBundleID(id string) error {
	if !bundleIDPattern.MatchString(id) {
		return errors.New("invalid bundle identifier")
	}
	return nil
}

func boundedBundleRead(file io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 4<<20 {
		return nil, errors.New("bundle member exceeds byte limit")
	}
	return data, nil
}

// VerifyPublishedBundle checks the committed object, every digest and each
// requested member before handing paths to the runtime. Partial objects, foreign
// files and cross-bundle selections never become deployment inputs.
func (r *Root) VerifyPublishedBundle(directory string, members ...string) error {
	clean := filepath.Clean(directory)
	if directory != clean || !strings.HasPrefix(clean, "bundles"+string(filepath.Separator)+".object-") || filepath.Dir(clean) != "bundles" {
		return errors.New("deployment requires a published bundle directory")
	}
	root, err := os.OpenRoot(r.path)
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Join(clean, ".manifest.json")
	data, err := readBundleManifest(root, name)
	if err != nil {
		return errors.New("missing bounded bundle manifest")
	}
	var manifest bundleManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Version != 1 || manifest.Directory != clean || validBundleID(manifest.ID) != nil || len(manifest.Files) == 0 || len(manifest.Files) > 128 {
		return errors.New("invalid bundle manifest")
	}
	commitName := filepath.Join("bundles", manifest.ID+".json")
	info, err := root.Lstat(commitName)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("bundle was not published")
	}
	commit, err := readBundleManifest(root, commitName)
	if err != nil || !bytes.Equal(commit, data) {
		return errors.New("bundle publication mismatch")
	}
	for path, digest := range manifest.Files {
		if rel, err := cleanRelative(path); err != nil || rel != path {
			return errors.New("invalid bundle member")
		}
		name := filepath.Join(clean, path)
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("bundle member is not a regular file")
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		data, err := boundedBundleRead(file)
		_ = file.Close()
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			return errors.New("published bundle digest mismatch")
		}
	}
	for _, member := range members {
		rel, err := filepath.Rel(clean, member)
		if err != nil || manifest.Files[rel] == "" {
			return errors.New("deployment member is outside the published bundle")
		}
	}
	return nil
}
