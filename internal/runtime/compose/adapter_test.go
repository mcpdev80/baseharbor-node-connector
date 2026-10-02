package compose

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
)

func TestResolveStagedComposeFiles(t *testing.T) {
	dir := t.TempDir()
	project := filepath.Join(dir, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	composePath := filepath.Join(project, "compose.yml")
	if err := os.WriteFile(composePath, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := fssecure.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewAdapter(bhruntime.Docker, root)
	resolvedProject, files, _, err := adapter.resolve("project", []string{"project/compose.yml"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if resolvedProject == "" || len(files) != 1 {
		t.Fatalf("unexpected resolution result: project=%q files=%v", resolvedProject, files)
	}
}

func TestResolveRejectsUnsupportedComposeExtension(t *testing.T) {
	dir := t.TempDir()
	project := filepath.Join(dir, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(project, "compose.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := fssecure.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewAdapter(bhruntime.Docker, root)
	if _, _, _, err := adapter.resolve("project", []string{"project/compose.txt"}, ""); err == nil {
		t.Fatal("expected unsupported extension to fail")
	}
}
