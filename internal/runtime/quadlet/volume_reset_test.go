package quadlet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

func TestPublishedVolumeResetRequiresOwnedTeardownAndPreservesForeignOrInUseData(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PATH", base)
	t.Setenv("BASEHARBOR_TEST_VOLUME_EXISTS", filepath.Join(base, "volume"))
	t.Setenv("BASEHARBOR_TEST_RESET_CALLS", filepath.Join(base, "calls"))
	t.Setenv("BASEHARBOR_TEST_VOLUME_LABELS", `[{"Labels":{"com.docker.compose.project":"owned"}}]`)
	for name, script := range map[string]string{
		"systemctl": "#!/bin/sh\nexit 0\n",
		"podman":    "#!/bin/sh\ncase \"$2\" in\nexists) [ -f \"$BASEHARBOR_TEST_VOLUME_EXISTS\" ] && exit 0; exit 1;;\ninspect) printf '%s\\n' \"$BASEHARBOR_TEST_VOLUME_LABELS\"; exit 0;;\nrm) printf '%s\\n' \"$*\" >> \"$BASEHARBOR_TEST_RESET_CALLS\"; [ \"$BASEHARBOR_TEST_IN_USE\" = yes ] && exit 2; /bin/rm \"$BASEHARBOR_TEST_VOLUME_EXISTS\"; exit 0;;\nesac\nexit 2\n",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := fssecure.OpenRoot(filepath.Join(base, "stage"))
	if err != nil {
		t.Fatal(err)
	}
	content := "[Volume]\nVolumeName=owned-data\nLabel=com.docker.compose.project=owned\n"
	directory, err := root.PublishBundle(context.Background(), "owned", []fssecure.BundleFile{{Path: "owned.volume", Data: []byte(content), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	manager, _ := NewManager(filepath.Join(base, "units"))
	ctx := context.Background()
	if err := manager.ApplyPublished(ctx, root, directory, "owned.volume", content, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("BASEHARBOR_TEST_VOLUME_EXISTS"), []byte("retained provider data"), 0600); err != nil {
		t.Fatal(err)
	}
	if manager.ResetPublishedVolume(ctx, root, directory, "owned.volume", content) == nil {
		t.Fatal("active resource unit permits reset")
	}
	if err := manager.Remove(ctx, "owned.volume"); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"changed-source", "foreign", "in-use"} {
		t.Run(scenario, func(t *testing.T) {
			selected := content
			if scenario == "changed-source" {
				selected += "# changed\n"
			}
			if scenario == "foreign" {
				t.Setenv("BASEHARBOR_TEST_VOLUME_LABELS", `[{"Labels":{"com.docker.compose.project":"foreign"}}]`)
			}
			if scenario == "in-use" {
				t.Setenv("BASEHARBOR_TEST_IN_USE", "yes")
			}
			if manager.ResetPublishedVolume(ctx, root, directory, "owned.volume", selected) == nil {
				t.Fatal("unsafe reset succeeded")
			}
			if data, err := os.ReadFile(os.Getenv("BASEHARBOR_TEST_VOLUME_EXISTS")); err != nil || string(data) != "retained provider data" {
				t.Fatal("unsafe reset removed data", err)
			}
		})
	}
	if err := manager.ResetPublishedVolume(ctx, root, directory, "owned.volume", content); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(os.Getenv("BASEHARBOR_TEST_VOLUME_EXISTS")); !os.IsNotExist(err) {
		t.Fatal("owned reset retained data")
	}
	calls, err := os.ReadFile(os.Getenv("BASEHARBOR_TEST_RESET_CALLS"))
	if err != nil || strings.Contains(string(calls), "-f") || strings.Count(string(calls), "volume rm owned-data") != 2 {
		t.Fatal("reset forced or replayed removal", string(calls), err)
	}
	before := string(calls)
	if err := manager.ResetPublishedVolume(ctx, root, directory, "owned.volume", content); err != nil {
		t.Fatal("exact absent reset was not idempotent", err)
	}
	calls, _ = os.ReadFile(os.Getenv("BASEHARBOR_TEST_RESET_CALLS"))
	if string(calls) != before {
		t.Fatal("absent reset repeated a mutation")
	}
}
