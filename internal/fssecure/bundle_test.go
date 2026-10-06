package fssecure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentPublicationPreservesOriginalAndForeignData(t *testing.T) {
	dir := t.TempDir()
	var winners atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			root, err := OpenRoot(dir)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := root.PublishBundle(context.Background(), "unique", []BundleFile{{Path: "compose.yml", Data: []byte("original")}}); err == nil {
				winners.Add(1)
			}
		}()
	}
	workers.Wait()
	if winners.Load() != 1 {
		t.Fatalf("immutable publication winners = %d", winners.Load())
	}
	root, _ := OpenRoot(dir)
	original, _ := os.ReadFile(filepath.Join(dir, "bundles", "unique.json"))
	if _, err := root.PublishBundle(context.Background(), "unique", []BundleFile{{Path: "compose.yml", Data: []byte("replacement")}}); err == nil {
		t.Fatal("existing bundle replaced")
	}
	current, _ := os.ReadFile(filepath.Join(dir, "bundles", "unique.json"))
	if string(current) != string(original) {
		t.Fatal("published manifest changed")
	}
	foreign := filepath.Join(dir, "bundles", "foreign.json")
	if err := os.WriteFile(foreign, []byte("foreign data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := root.PublishBundle(context.Background(), "foreign", []BundleFile{{Path: "compose.yml", Data: []byte("replacement")}}); err == nil {
		t.Fatal("foreign publication name replaced")
	}
	if data, err := os.ReadFile(foreign); err != nil || string(data) != "foreign data" {
		t.Fatal("foreign data damaged")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "bundles"))
	if len(entries) != 3 {
		t.Fatalf("failed publication leaked objects: %d", len(entries))
	}
}

type interruptedContext struct {
	context.Context
	checks int
}

func (c *interruptedContext) Err() error {
	c.checks++
	if c.checks > 1 {
		return context.Canceled
	}
	return nil
}

func TestInterruptedOrPartialBundleCannotBeConsumed(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &interruptedContext{Context: context.Background()}
	_, err = root.PublishBundle(ctx, "interrupted", []BundleFile{{Path: "one.yml", Data: []byte("first")}, {Path: "two.yml", Data: []byte("second")}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("interruption = %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "bundles"))
	if len(entries) != 0 {
		t.Fatal("interrupted transfer retained deployable data")
	}
	directory, err := root.PublishBundle(context.Background(), "committed", []BundleFile{{Path: "compose.yml", Data: []byte("original")}})
	if err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(directory, "compose.yml")
	if err := root.VerifyPublishedBundle(directory, member); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "bundles", "committed.json")); err != nil {
		t.Fatal(err)
	}
	if err := root.VerifyPublishedBundle(directory, member); err == nil {
		t.Fatal("orphaned object consumed")
	}
}

func TestPublishedBundleRejectsTamperAndCrossBundleMembers(t *testing.T) {
	dir := t.TempDir()
	root, _ := OpenRoot(dir)
	files := []BundleFile{{Path: "compose.yml", Data: []byte("original")}}
	first, err := root.PublishBundle(context.Background(), "first", files)
	if err != nil {
		t.Fatal(err)
	}
	second, err := root.PublishBundle(context.Background(), "second", files)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.VerifyPublishedBundle(first, filepath.Join(second, "compose.yml")); err == nil {
		t.Fatal("cross-bundle member consumed")
	}
	if err := os.WriteFile(filepath.Join(dir, first, "compose.yml"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.VerifyPublishedBundle(first, filepath.Join(first, "compose.yml")); err == nil {
		t.Fatal("tampered bundle consumed")
	}
}
