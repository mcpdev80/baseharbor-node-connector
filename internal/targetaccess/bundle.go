package targetaccess

import (
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

func StageBundle(root *fssecure.Root, bundle Bundle) (StagedBundle, error) {
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
	for _, file := range bundle.Files {
		path := filepath.Clean(strings.TrimSpace(file.Path))
		if path == "." || path == "" {
			return StagedBundle{}, errors.New("bundle file path is required")
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
		stagedPath := filepath.Join("bundles", bundleID, path)
		written, err := root.WriteFile(stagedPath, file.Data, fs.FileMode(mode&0o700))
		if err != nil {
			return StagedBundle{}, fmt.Errorf("stage %q: %w", path, err)
		}
		rel, err := filepath.Rel(root.Path(), written)
		if err != nil {
			return StagedBundle{}, err
		}
		result.Files = append(result.Files, StagedFile{Path: rel, SHA256: actual})
	}
	return result, nil
}
