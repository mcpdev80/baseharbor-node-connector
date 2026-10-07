package quadlet

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

func publishedFixture(t *testing.T, content string, envMode os.FileMode) (*fssecure.Root, string) {
	t.Helper()
	root, err := fssecure.OpenRoot(filepath.Join(t.TempDir(), "node files %literal"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := root.PublishBundle(context.Background(), "fixture", []fssecure.BundleFile{
		{Path: "owned.container", Data: []byte(content), Mode: 0600},
		{Path: "tls/key.pem", Data: []byte("fixture-key"), Mode: 0644},
		{Path: "owned.env", Data: []byte("PASSWORD=fixture\n"), Mode: envMode},
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, directory
}

func TestPublishedQuadletBindsExactNodeFilesAndNodeRuntimeDefaults(t *testing.T) {
	content := "[Container]\nImage=example:fixture\nVolume=@BASEHARBOR_BUNDLE@/tls/key.pem:/run/key.pem:ro\nEnvironmentFile=@BASEHARBOR_BUNDLE@/owned.env\n"
	root, directory := publishedFixture(t, content, 0600)
	t.Setenv("CONTAINERS_STORAGE_CONF", "/node/storage.conf")
	resolved, err := resolvePublishedContent(root, directory, "owned.container", content)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(root.Path(), directory, "tls/key.pem")
	for _, expected := range []string{
		"Volume=" + strings.ReplaceAll(key, "%", "%%") + ":/run/key.pem:ro",
		"Environment=" + strconv.Quote("CONTAINERS_STORAGE_CONF=/node/storage.conf"),
	} {
		if !strings.Contains(resolved, expected) {
			t.Fatal("missing node-local resolution", expected)
		}
	}
	if strings.Contains(resolved, "@BASEHARBOR_BUNDLE@") {
		t.Fatal("unresolved bundle path")
	}
	if _, err := resolvePublishedContent(root, directory, "owned.container", content+"# changed\n"); err == nil {
		t.Fatal("changed Core source admitted")
	}
	if err := os.Chmod(key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolvePublishedContent(root, directory, "owned.container", content); err == nil {
		t.Fatal("changed committed bind mode admitted")
	}
}

func TestPublishedQuadletRejectsUnsafeBindingsBeforeNativeMutation(t *testing.T) {
	for _, line := range []string{
		"Volume=@BASEHARBOR_BUNDLE@/../foreign:/run/key:ro",
		"Volume=@BASEHARBOR_BUNDLE@/tls/key.pem:/run/key:rw",
		"Volume=@BASEHARBOR_BUNDLE@/missing.pem:/run/key:ro",
		"Volume=/core/checkout/key.pem:/run/key:ro",
		"EnvironmentFile=./owned.env",
		"EnvironmentFile=@BASEHARBOR_BUNDLE@/tls/key.pem",
		"Exec=cat @BASEHARBOR_BUNDLE@/tls/key.pem",
		"EnvironmentFile=@BASEHARBOR_BUNDLE@/owned.env\\",
	} {
		t.Run(line, func(t *testing.T) {
			content := "[Container]\nImage=example:fixture\n" + line + "\n"
			root, directory := publishedFixture(t, content, 0600)
			manager, _ := NewManager(filepath.Join(t.TempDir(), "units"))
			if err := manager.ApplyPublished(context.Background(), root, directory, "owned.container", content, true); err == nil {
				t.Fatal("unsafe published binding admitted")
			}
			if _, err := os.Stat(manager.baseDir); !os.IsNotExist(err) {
				t.Fatal("unsafe source mutated unit storage")
			}
		})
	}
	content := "[Container]\nEnvironmentFile=@BASEHARBOR_BUNDLE@/owned.env\n"
	root, directory := publishedFixture(t, content, 0644)
	if _, err := resolvePublishedContent(root, directory, "owned.container", content); err == nil {
		t.Fatal("public runtime environment admitted")
	}
}

func TestPublishedQuadletPreservesForeignNativeResourceWithMatchingName(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	// A native resource exists, but no protected unit realization authorizes it.
	if err := os.WriteFile(filepath.Join(bin, "podman"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	content := "[Container]\nImage=example:fixture\nContainerName=owned\nLabel=com.docker.compose.project=project\nLabel=com.docker.compose.service=workload\n"
	root, directory := publishedFixture(t, content, 0600)
	manager, _ := NewManager(filepath.Join(dir, "units"))
	if err := manager.ApplyPublished(context.Background(), root, directory, "owned.container", content, true); err == nil {
		t.Fatal("foreign native resource was adopted")
	}
	if _, err := os.Stat(manager.baseDir); !os.IsNotExist(err) {
		t.Fatal("native collision mutated unit storage")
	}
}
