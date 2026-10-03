package fssecure

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExistingAllowsRootAndChild(t *testing.T) {
	rootDir := t.TempDir()
	root, err := OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Existing("."); err != nil {
		t.Fatalf("root should be allowed: %v", err)
	}
	child := filepath.Join(rootDir, "app")
	if err := os.MkdirAll(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Existing("app"); err != nil {
		t.Fatalf("child should be allowed: %v", err)
	}
}

func TestExistingRejectsTraversal(t *testing.T) {
	parent := t.TempDir()
	rootDir := filepath.Join(parent, "stage")
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Existing("../outside"); err == nil {
		t.Fatal("expected traversal to be rejected")
	}
}

func TestExistingRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	parent := t.TempDir()
	rootDir := filepath.Join(parent, "stage")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootDir, "escape")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Existing("escape"); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestWriteFileRejectsSymlinkParentEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	parent := t.TempDir()
	rootDir := filepath.Join(parent, "stage")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(rootDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootDir, "escape")); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.WriteFile(filepath.Join("escape", "payload.txt"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected staged write through symlink parent to be rejected")
	}
}
