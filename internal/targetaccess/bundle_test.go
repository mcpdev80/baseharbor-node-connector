package targetaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

func TestStageBundleWritesVerifiedFilesInsideStagingRoot(t *testing.T) {
	root, err := fssecure.OpenRoot(filepath.Join(t.TempDir(), "staging"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("services:\n  app:\n    image: example/app:v1\n")
	sum := sha256.Sum256(data)
	result, err := StageBundle(context.Background(), root, Bundle{
		BundleID: "deploy-1",
		Files: []BundleFile{{
			Path:   "compose.yaml",
			SHA256: hex.EncodeToString(sum[:]),
			Mode:   0o600,
			Data:   data,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Files) != 1 {
		t.Fatalf("staged files = %d", len(result.Files))
	}
	path := filepath.Join(root.Path(), result.Files[0].Path)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatal("staged data mismatch")
	}
}

func TestStageBundleRejectsTraversalAndHashMismatch(t *testing.T) {
	root, err := fssecure.OpenRoot(filepath.Join(t.TempDir(), "staging"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = StageBundle(context.Background(), root, Bundle{
		BundleID: "deploy-1",
		Files:    []BundleFile{{Path: "../escape", SHA256: "deadbeef", Data: []byte("x")}},
	})
	if err == nil {
		t.Fatal("bundle traversal unexpectedly accepted")
	}
	_, err = StageBundle(context.Background(), root, Bundle{
		BundleID: "deploy-1",
		Files:    []BundleFile{{Path: "safe.txt", SHA256: "deadbeef", Data: []byte("x")}},
	})
	if err == nil {
		t.Fatal("hash mismatch unexpectedly accepted")
	}
}

func TestLaterHashMismatchPublishesNoEarlierValidFile(t *testing.T) {
	root, err := fssecure.OpenRoot(filepath.Join(t.TempDir(), "staging"))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("first valid file")
	sum := sha256.Sum256(data)
	_, err = StageBundle(context.Background(), root, Bundle{BundleID: "atomic", Files: []BundleFile{
		{Path: "first.yml", SHA256: hex.EncodeToString(sum[:]), Data: data},
		{Path: "second.yml", SHA256: "invalid", Data: []byte("second")},
	}})
	if err == nil {
		t.Fatal("later hash mismatch accepted")
	}
	entries, err := os.ReadDir(root.Path())
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid bundle published an earlier valid member")
	}
}
