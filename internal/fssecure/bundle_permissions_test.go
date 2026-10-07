package fssecure

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReadableBindFilesRetainProtectedAncestorsAndExactModes(t *testing.T) {
	root, err := OpenRoot(filepath.Join(t.TempDir(), "staging"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := root.PublishBundle(context.Background(), "tls", []BundleFile{
		{Path: "tls/key.pem", Data: []byte("private-key-fixture"), Mode: 0644},
		{Path: "runtime.env", Data: []byte("PASSWORD=protected-fixture"), Mode: 0600},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]os.FileMode{"tls/key.pem": 0644, "runtime.env": 0600} {
		info, err := os.Stat(filepath.Join(root.Path(), dir, name))
		if err != nil || info.Mode().Perm() != expected {
			t.Fatal("source permissions changed", name, err)
		}
	}
	for _, name := range []string{".", "bundles", dir, filepath.Join(dir, "tls")} {
		info, err := os.Stat(filepath.Join(root.Path(), name))
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatal("readable bind material exposed by an ancestor", name, err)
		}
	}
	if err := root.VerifyPublishedBundle(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root.Path(), dir, "tls/key.pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if root.VerifyPublishedBundle(dir) == nil {
		t.Fatal("changed bind-file permissions admitted")
	}
}

func TestLegacyOwnerOnlyPublicationRemainsReadable(t *testing.T) {
	root, err := OpenRoot(filepath.Join(t.TempDir(), "staging"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := root.PublishBundle(context.Background(), "legacy", []BundleFile{{Path: "compose.yml", Data: []byte("services: {}")}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root.Path(), dir, ".manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest bundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Version = 1
	manifest.Modes = nil
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	// The original publication has a hard-linked commit and object manifest.
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.VerifyPublishedBundle(dir); err != nil {
		t.Fatal("legacy owner-only publication rejected", err)
	}
	if err := os.Chmod(filepath.Join(root.Path(), dir, "compose.yml"), 0644); err != nil {
		t.Fatal(err)
	}
	if root.VerifyPublishedBundle(dir) == nil {
		t.Fatal("legacy owner-only publication gained public file rights")
	}
}

func TestBundleRejectsPublicRootsParentsAndUnsupportedModes(t *testing.T) {
	public := t.TempDir()
	if err := os.Chmod(public, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRoot(public); err == nil {
		t.Fatal("public staging root admitted")
	}
	for _, mode := range []os.FileMode{0666, 0777, 0640, os.ModeSetuid | 0700} {
		root, err := OpenRoot(filepath.Join(t.TempDir(), "staging"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := root.PublishBundle(context.Background(), "invalid", []BundleFile{{Path: "key.pem", Data: []byte("secret"), Mode: mode}}); err == nil {
			t.Fatal("unsupported permissions admitted", mode)
		}
		entries, err := os.ReadDir(root.Path())
		if err != nil || len(entries) != 0 {
			t.Fatal("invalid permissions published material", err)
		}
	}
	for _, parent := range []string{"root", "storage", "object", "nested"} {
		root, err := OpenRoot(filepath.Join(t.TempDir(), "staging"))
		if err != nil {
			t.Fatal(err)
		}
		dir, err := root.PublishBundle(context.Background(), "tls", []BundleFile{{Path: "tls/key.pem", Data: []byte("secret"), Mode: 0644}})
		if err != nil {
			t.Fatal(err)
		}
		name := map[string]string{"root": ".", "storage": "bundles", "object": dir, "nested": filepath.Join(dir, "tls")}[parent]
		if err := os.Chmod(filepath.Join(root.Path(), name), 0755); err != nil {
			t.Fatal(err)
		}
		if root.VerifyPublishedBundle(dir) == nil {
			t.Fatal("public bundle ancestor admitted", parent)
		}
	}
}
