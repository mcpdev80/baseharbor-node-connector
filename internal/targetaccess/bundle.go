package targetaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

type Bundle struct {
	BundleID string       `json:"bundle_id"`
	Files    []BundleFile `json:"files"`
}

type BundleFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode,omitempty"`
	Data   []byte `json:"data"`
}

type StagedBundle struct {
	BundleID string       `json:"bundle_id"`
	Files    []StagedFile `json:"files"`
}

type StagedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func StageBundle(ctx context.Context, root *fssecure.Root, bundle Bundle) (StagedBundle, error) {
	if root == nil {
		return StagedBundle{}, errors.New("staging root is required")
	}
	bundleID := strings.TrimSpace(bundle.BundleID)
	if bundleID == "" || strings.ContainsAny(bundleID, "/\\\x00\r\n") {
		return StagedBundle{}, errors.New("invalid bundle_id")
	}
	if len(bundle.Files) == 0 {
		return StagedBundle{}, errors.New("bundle must contain at least one file")
	}

	result := StagedBundle{BundleID: bundleID}
	seen := map[string]struct{}{}
	files := make([]fssecure.BundleFile, 0, len(bundle.Files))
	for _, file := range bundle.Files {
		rawPath := strings.TrimSpace(file.Path)
		if rawPath == "" || filepath.IsAbs(rawPath) {
			return StagedBundle{}, errors.New("bundle file path must be relative")
		}
		path := filepath.Clean(rawPath)
		if path == "." || path == ".." || strings.HasPrefix(path, ".."+string(filepath.Separator)) {
			return StagedBundle{}, errors.New("bundle file path escapes bundle root")
		}
		if _, exists := seen[path]; exists {
			return StagedBundle{}, fmt.Errorf("duplicate bundle file path %q", path)
		}
		seen[path] = struct{}{}

		sum := sha256.Sum256(file.Data)
		actual := hex.EncodeToString(sum[:])
		expected := strings.ToLower(strings.TrimSpace(file.SHA256))
		if expected == "" || expected != actual {
			return StagedBundle{}, fmt.Errorf("sha256 mismatch for %q", path)
		}

		mode := file.Mode
		if mode == 0 {
			mode = 0o600
		}
		files = append(files, fssecure.BundleFile{Path: path, Data: file.Data, Mode: fs.FileMode(mode & 0o700)})
		result.Files = append(result.Files, StagedFile{Path: path, SHA256: actual})
	}
	directory, err := root.PublishBundle(ctx, bundleID, files)
	if err != nil {
		return StagedBundle{}, err
	}
	for i := range result.Files {
		result.Files[i].Path = filepath.Join(directory, result.Files[i].Path)
	}
	return result, nil
}
