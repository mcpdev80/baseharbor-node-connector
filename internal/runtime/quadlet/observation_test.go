package quadlet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

func TestPublishedUnitObservationRejectsSubstitutedSourceAndIncompleteNativeEvidence(t *testing.T) {
	base := t.TempDir()
	marker := filepath.Join(base, "calls")
	t.Setenv("BASEHARBOR_TEST_UNIT_CALLS", marker)
	t.Setenv("PATH", base)
	for name, script := range map[string]string{
		"systemctl": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BASEHARBOR_TEST_UNIT_CALLS\"\nif [ \"$2\" = show ]; then printf '%s\\n' \"$BASEHARBOR_TEST_UNIT_STATE\"; fi\n",
		"podman":    "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := fssecure.OpenRoot(filepath.Join(base, "stage"))
	if err != nil {
		t.Fatal(err)
	}
	content := "[Container]\nImage=example/fixture:exact\nContainerName=init\nLabel=com.docker.compose.project=owned\nLabel=com.docker.compose.service=init\n"
	directory, err := root.PublishBundle(context.Background(), "owned", []fssecure.BundleFile{{Path: "init.container", Data: []byte(content), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(filepath.Join(base, "units"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ApplyPublished(context.Background(), root, directory, "init.container", content, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	state := "Id=init.service\nLoadState=loaded\nSourcePath=" + filepath.Join(manager.baseDir, "init.container") + "\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=1\nExecMainStatus=0\nExecMainStartTimestampMonotonic=100\nExecMainExitTimestampMonotonic=200\n"
	t.Setenv("BASEHARBOR_TEST_UNIT_STATE", state)
	observed, err := manager.ObservePublished(context.Background(), root, directory, "init.container", content)
	if err != nil || observed.Name != "init.container" || observed.Unit != "init.service" || observed.StartedMicros != 100 || observed.FinishedMicros != 200 || observed.ObservedAt.IsZero() {
		t.Fatal("verified unit evidence lost", err)
	}
	for _, bad := range []string{
		strings.Replace(state, "Id=init.service", "Id=foreign.service", 1),
		strings.Replace(state, "LoadState=loaded", "LoadState=not-found", 1),
		strings.Replace(state, filepath.Join(manager.baseDir, "init.container"), "/foreign/init.container", 1),
		strings.Replace(state, "ExecMainStatus=0\n", "", 1),
		strings.Replace(state, "ExecMainCode=1", "ExecMainCode=invalid", 1),
		strings.Replace(state, "ExecMainStatus=0", "ExecMainStatus=-1", 1),
		strings.Replace(state, "ExecMainStartTimestampMonotonic=100", "ExecMainStartTimestampMonotonic=invalid", 1),
		state + "ExecMainStatus=0\n",
	} {
		t.Setenv("BASEHARBOR_TEST_UNIT_STATE", bad)
		if _, err := manager.ObservePublished(context.Background(), root, directory, "init.container", content); err == nil {
			t.Fatal("unverified native unit evidence accepted")
		}
	}
	if calls, err := os.ReadFile(marker); err != nil || strings.Contains(string(calls), "restart") || strings.Contains(string(calls), "start ") || strings.Contains(string(calls), "stop ") {
		t.Fatal("observation mutated a service", err)
	}
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ObservePublished(context.Background(), root, directory, "init.container", content+"# changed\n"); err == nil {
		t.Fatal("different Core source accepted")
	}
	foreign := filepath.Join(manager.baseDir, "foreign.container")
	if err := os.WriteFile(foreign, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ObservePublished(context.Background(), root, directory, "foreign.container", content); err == nil {
		t.Fatal("foreign unit adopted")
	}
	if calls, err := os.ReadFile(marker); err != nil || len(calls) != 0 {
		t.Fatal("rejected source reached systemd", err)
	}

	if err := os.WriteFile(filepath.Join(manager.baseDir, "init.container"), []byte(content+"# altered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.ObservePublished(context.Background(), root, directory, "init.container", content); err == nil {
		t.Fatal("altered owned unit accepted")
	}
	if calls, err := os.ReadFile(marker); err != nil || len(calls) != 0 {
		t.Fatal("altered unit reached systemd", err)
	}

}
