//go:build linux

package quadlet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

func TestNativePublishedCompletion(t *testing.T) {
	if os.Getenv("BASEHARBOR_NATIVE_QUADLET_COMPLETION") != "1" {
		t.Skip("explicit native rootless Quadlet qualification")
	}
	image := os.Getenv("BASEHARBOR_CONNECTOR_RUNTIME_IMAGE")
	if !strings.Contains(image, "@sha256:") || os.Getenv("XDG_RUNTIME_DIR") == "" {
		t.Fatal("immutable fixture image and native user manager are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "podman", "info", "--format", "{{.Host.Security.Rootless}}").Output(); err != nil || strings.TrimSpace(string(out)) != "true" {
		t.Fatal("rootless Podman required", err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	project := "baha-init-proof-" + hex.EncodeToString(nonce[:])
	manager, err := NewManager(filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "containers", "systemd"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := fssecure.OpenRoot(filepath.Join(t.TempDir(), "stage"))
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"success", "failed", "unstarted"} {
		t.Run(scenario, func(t *testing.T) {
			name := project + "-" + scenario
			file := name + ".container"
			exit := "0"
			if scenario == "failed" {
				exit = "17"
			}
			content := "[Container]\nImage=" + image + "\nContainerName=" + name + "\nUser=1000:1000\nReadOnly=true\nExec=/bin/sh -ec \"sleep 1; exit " + exit + "\"\nLabel=baseharbor.enrollment-qualification=true\nLabel=com.docker.compose.project=" + project + "\nLabel=com.docker.compose.service=" + scenario + "\n[Service]\nTimeoutStartSec=30\n"
			directory, err := root.PublishBundle(ctx, name, []fssecure.BundleFile{{Path: file, Data: []byte(content), Mode: 0600}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
				defer stop()
				if err := manager.Remove(cleanup, file); err != nil {
					t.Error("owned native completion cleanup failed", err)
				}
				if _, err := os.Stat(filepath.Join(manager.baseDir, executionBindingName(file))); !os.IsNotExist(err) {
					t.Error("current execution receipt survived removal", err)
				}
			})
			err = manager.ApplyPublished(ctx, root, directory, file, content, scenario != "unstarted")
			if err != nil && scenario != "failed" {
				t.Fatal("native published init apply failed", err)
			}
			if scenario != "unstarted" {
				deadline := time.Now().Add(10 * time.Second)
				for {
					observation, err := manager.ObservePublished(ctx, root, directory, file, content)
					if err != nil {
						// A short-lived native container can disappear between
						// exists and inspect. Repeat only the bounded read-only
						// observation; successful settled evidence is mandatory.
						if time.Now().After(deadline) || ctx.Err() != nil {
							t.Fatal("native init evidence unavailable within convergence bound", err)
						}
						time.Sleep(100 * time.Millisecond)
						continue
					}
					settled := (observation.ActiveState == "inactive" && observation.SubState == "dead") || observation.ActiveState == "failed" || (observation.ActiveState == "active" && observation.SubState == "exited")
					if observation.FinishedMicros != 0 && settled {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("native init did not settle: %+v", observation)
					}
					time.Sleep(100 * time.Millisecond)
				}
			}
			err = manager.VerifyPublishedCompletion(ctx, root, directory, file, content)
			if scenario == "success" && err != nil {
				observation, probeErr := manager.ObservePublished(ctx, root, directory, file, content)
				t.Fatalf("current native success denied: %v; observation=%+v; observation_error=%v", err, observation, probeErr)
			}
			if scenario != "success" && err == nil {
				t.Fatal("failed or unstarted native unit accepted")
			}
			if scenario == "success" {
				changed := content + "# new deployment source\n"
				newDirectory, err := root.PublishBundle(ctx, name+"-changed", []fssecure.BundleFile{{Path: file, Data: []byte(changed), Mode: 0600}})
				if err != nil {
					t.Fatal(err)
				}
				if err := manager.ApplyPublished(ctx, root, newDirectory, file, changed, false); err != nil {
					t.Fatal(err)
				}
				if manager.VerifyPublishedCompletion(ctx, root, newDirectory, file, changed) == nil {
					t.Fatal("new source adopted old native success")
				}
			}
		})
	}
	if !t.Failed() {
		t.Log("native rootless unit completion verified exact published source and current boot activation; successful exit 0 accepted, failure exit 17 and never-started denied, changed source cannot adopt old success; transport and full Application lifecycle not qualified")
	}
}
