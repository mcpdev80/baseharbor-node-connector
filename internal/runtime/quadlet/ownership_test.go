package quadlet

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNativeUnitNamesAndForeignArtifactsArePreserved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix source command spy")
	}
	dir := t.TempDir()
	bin, units := filepath.Join(dir, "bin"), filepath.Join(dir, "units")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(units, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "calls")
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	manager, err := NewManager(units)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(units, "foreign.container")
	if err := os.WriteFile(foreign, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), "foreign.container", "replacement", true); err == nil {
		t.Fatal("foreign unit overwritten")
	}
	if err := manager.Remove(context.Background(), "foreign.container"); err == nil {
		t.Fatal("foreign unit removed")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("foreign unit caused a runtime side effect")
	}
	if data, _ := os.ReadFile(foreign); string(data) != "foreign" {
		t.Fatal("foreign artifact changed")
	}
	content := "[Container]\nImage=example/image:fixture\n"
	if err := manager.Apply(context.Background(), "managed.container", content, true); err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), "managed.container", content, true); err != nil {
		t.Fatal("verified repair failed", err)
	}
	if err := manager.Disable(context.Background(), "managed.container"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Enable(context.Background(), "managed.container"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Remove(context.Background(), "managed.container"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(units, "managed.container")); !os.IsNotExist(err) {
		t.Fatal("owned unit was not removed")
	}
	data, _ := os.ReadFile(marker)
	if strings.Contains(string(data), "--user enable") || strings.Contains(string(data), "--user disable") {
		t.Fatal("generated service was managed as a regular installed unit")
	}
	for _, expected := range []string{"--user daemon-reload", "--user restart managed.service", "--user start managed.service", "--user stop managed.service"} {
		if !strings.Contains(string(data), expected) {
			t.Fatalf("missing native generated service action %q", expected)
		}
	}
	for name, expected := range map[string]string{"app.container": "app.service", "app.network": "app-network.service", "app.volume": "app-volume.service", "app.image": "app-image.service", "app.build": "app-build.service", "app.pod": "app-pod.service"} {
		if unitName(name) != expected {
			t.Fatalf("native generated unit for %s = %s", name, unitName(name))
		}
	}
}

func TestModifiedManagedArtifactCannotAuthorizeDestruction(t *testing.T) {
	dir := t.TempDir()
	manager, _ := NewManager(filepath.Join(dir, "units"))
	if err := manager.writeOwned(context.Background(), "managed.container", []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manager.baseDir, "managed.container"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.verifyOwned("managed.container"); err == nil {
		t.Fatal("changed realization authorized ownership")
	}
	if err := manager.Remove(context.Background(), "managed.container"); err == nil {
		t.Fatal("changed realization removed")
	}
}
