package compose

import (
	"context"
	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
	"path/filepath"
	"testing"
)

func TestResolveConsumesOnlyCommittedMembers(t *testing.T) {
	root, err := fssecure.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := root.PublishBundle(context.Background(), "deployment", []fssecure.BundleFile{{Path: "compose.yml", Data: []byte("services: {}\n")}, {Path: "compose.txt", Data: []byte("not compose")}})
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewAdapter(bhruntime.Docker, root)
	if _, files, _, err := adapter.resolve(directory, []string{filepath.Join(directory, "compose.yml")}, ""); err != nil || len(files) != 1 {
		t.Fatalf("published compose rejected: %v", err)
	}
	for _, file := range []string{"foreign/compose.yml", filepath.Join(directory, "compose.txt")} {
		if _, _, _, err := adapter.resolve(directory, []string{file}, ""); err == nil {
			t.Fatal("invalid deployment input accepted")
		}
	}
	if _, _, _, err := adapter.resolve("project", []string{"project/compose.yml"}, ""); err == nil {
		t.Fatal("unpublished project accepted")
	}
}
