package quadlet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

func TestPublishedOwnershipInspectionSharesRealizationLock(t *testing.T) {
	base := t.TempDir()
	marker := filepath.Join(base, "native-inspection")
	t.Setenv("BASEHARBOR_TEST_NATIVE_CALL", marker)
	t.Setenv("PATH", base)
	if err := os.WriteFile(filepath.Join(base, "podman"), []byte("#!/bin/sh\nprintf inspected > \"$BASEHARBOR_TEST_NATIVE_CALL\"\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	content := "[Container]\nImage=example:fixture\nContainerName=owned\nLabel=com.docker.compose.project=project\nLabel=com.docker.compose.service=workload\n"
	root, directory := publishedFixture(t, content, 0600)
	manager, _ := NewManager(filepath.Join(base, "units"))
	release, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := manager.ApplyPublished(ctx, root, directory, "owned.container", content, true); err == nil {
		t.Fatal("published apply bypassed the held realization lock")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("native ownership was inspected outside the realization lock", err)
	}
}

func TestPublishedQuadletReusesRetainedOwnedVolumeAfterOrdinaryRemove(t *testing.T) {
	for _, changed := range []string{"unchanged", "foreign-label", "foreign-unit", "changed-source", "corrupt-receipt"} {
		t.Run(changed, func(t *testing.T) {
			base := t.TempDir()
			bin := filepath.Join(base, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			podman := "#!/bin/sh\ncase \"$2\" in\nexists) [ -f \"$BASEHARBOR_TEST_NATIVE_EXISTS\" ] && exit 0; exit 1;;\ninspect) printf '%s\\n' \"$BASEHARBOR_TEST_NATIVE_INSPECT\"; exit 0;;\nesac\nexit 2\n"
			for name, script := range map[string]string{"podman": podman, "systemctl": "#!/bin/sh\nexit 0\n"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			flag := filepath.Join(base, "native-resource-exists")
			t.Setenv("BASEHARBOR_TEST_NATIVE_EXISTS", flag)
			t.Setenv("BASEHARBOR_TEST_NATIVE_INSPECT", `[{"Labels":{"com.docker.compose.project":"project"}}]`)
			root, err := fssecure.OpenRoot(filepath.Join(base, "staging"))
			if err != nil {
				t.Fatal(err)
			}
			content := "[Volume]\nVolumeName=owned-data\nLabel=com.docker.compose.project=project\n"
			publish := func(id, content string) string {
				t.Helper()
				directory, err := root.PublishBundle(context.Background(), id, []fssecure.BundleFile{{Path: "owned.volume", Data: []byte(content), Mode: 0600}})
				if err != nil {
					t.Fatal(err)
				}
				return directory
			}
			directory := publish("original", content)
			manager, _ := NewManager(filepath.Join(base, "units"))
			if err := manager.ApplyPublished(context.Background(), root, directory, "owned.volume", content, false); err != nil {
				t.Fatal(err)
			}
			resolved, err := resolvePublishedContent(root, directory, "owned.volume", content)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(flag, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := manager.Remove(context.Background(), "owned.volume"); err != nil {
				t.Fatal(err)
			}
			if err := manager.verifyRetainedResource("owned.volume", []byte(resolved)); err != nil {
				t.Fatal("retained exact realization receipt cannot be verified", err)
			}
			switch changed {
			case "foreign-label":
				t.Setenv("BASEHARBOR_TEST_NATIVE_INSPECT", `[{"Labels":{"com.docker.compose.project":"foreign"}}]`)
			case "foreign-unit":
				if err := os.WriteFile(filepath.Join(manager.baseDir, "owned.volume"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-source":
				content += "# different desired source\n"
				directory = publish("changed", content)
			case "corrupt-receipt":
				store, _ := manager.store()
				retained, err := store.PublishedBundleDirectory(artifactID("owned.volume", []byte(resolved)))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(store.Path(), retained, "owned.volume"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err = manager.ApplyPublished(context.Background(), root, directory, "owned.volume", content, false)
			if changed == "unchanged" && err != nil {
				t.Fatal("ordinary removal lost retained provider ownership", err)
			}
			if changed != "unchanged" && err == nil {
				t.Fatal("changed/foreign retained resource adopted", changed)
			}
			if changed == "foreign-unit" {
				data, err := os.ReadFile(filepath.Join(manager.baseDir, "owned.volume"))
				if err != nil || string(data) != "foreign" {
					t.Fatal("foreign unit was changed", err)
				}
			} else if changed != "unchanged" {
				if _, err := os.Lstat(filepath.Join(manager.baseDir, "owned.volume")); !os.IsNotExist(err) {
					t.Fatal("rejected retained resource created an active unit", err)
				}
			}
		})
	}
}
