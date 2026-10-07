//go:build linux

package quadlet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

func TestCompletionRequiresExecutionOfCurrentSourceOnCurrentBoot(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PATH", base)
	for name, script := range map[string]string{
		"systemctl": "#!/bin/sh\nif [ \"$2\" = show ]; then printf '%s\\n' \"$BASEHARBOR_TEST_UNIT_STATE\"; fi\n",
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
	content := "[Container]\nImage=example:fixture\nContainerName=init\nLabel=com.docker.compose.project=owned\nLabel=com.docker.compose.service=init\n"
	directory, err := root.PublishBundle(context.Background(), "owned", []fssecure.BundleFile{{Path: "init.container", Data: []byte(content), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(filepath.Join(base, "units"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := manager.ApplyPublished(ctx, root, directory, "init.container", content, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(manager.baseDir, executionBindingName("init.container")))
	var binding executionBinding
	if err != nil || json.Unmarshal(data, &binding) != nil {
		t.Fatal("execution binding was not retained", err)
	}
	state := fmt.Sprintf("Id=init.service\nLoadState=loaded\nSourcePath=%s\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=1\nExecMainStatus=0\nExecMainStartTimestampMonotonic=%d\nExecMainExitTimestampMonotonic=%d\n", filepath.Join(manager.baseDir, "init.container"), binding.NotBeforeMicros+1, binding.NotBeforeMicros+2)
	t.Setenv("BASEHARBOR_TEST_UNIT_STATE", state)
	if err := manager.VerifyPublishedCompletion(ctx, root, directory, "init.container", content); err != nil {
		t.Fatal("current successful execution denied", err)
	}
	for _, bad := range []string{
		strings.Replace(state, fmt.Sprintf("ExecMainStartTimestampMonotonic=%d", binding.NotBeforeMicros+1), fmt.Sprintf("ExecMainStartTimestampMonotonic=%d", binding.NotBeforeMicros-1), 1),
		strings.Replace(state, "ExecMainStatus=0", "ExecMainStatus=17", 1),
		strings.Replace(state, "ExecMainCode=1", "ExecMainCode=2", 1),
		strings.Replace(state, "Result=success", "Result=exit-code", 1),
		strings.Replace(state, "ActiveState=inactive", "ActiveState=activating", 1),
		strings.Replace(state, "SubState=dead", "SubState=running", 1),
		strings.Replace(state, fmt.Sprintf("ExecMainExitTimestampMonotonic=%d", binding.NotBeforeMicros+2), "ExecMainExitTimestampMonotonic=0", 1),
		strings.Replace(state, fmt.Sprintf("ExecMainExitTimestampMonotonic=%d", binding.NotBeforeMicros+2), "ExecMainExitTimestampMonotonic=18446744073709551615", 1),
	} {
		t.Setenv("BASEHARBOR_TEST_UNIT_STATE", bad)
		if manager.VerifyPublishedCompletion(ctx, root, directory, "init.container", content) == nil {
			t.Fatal("stale or unsuccessful execution accepted")
		}
	}
	t.Setenv("BASEHARBOR_TEST_UNIT_STATE", state)
	for _, changed := range []executionBinding{
		{binding.SourceSHA256, "foreign-boot", binding.NotBeforeMicros},
		{"foreign-source", binding.BootID, binding.NotBeforeMicros},
		{binding.SourceSHA256, binding.BootID, 0},
		{binding.SourceSHA256, binding.BootID, ^uint64(0)},
	} {
		bytes, _ := json.Marshal(changed)
		if err := manager.writeOwned(ctx, executionBindingName("init.container"), bytes); err != nil {
			t.Fatal(err)
		}
		if manager.VerifyPublishedCompletion(ctx, root, directory, "init.container", content) == nil {
			t.Fatal("different execution binding accepted")
		}
	}
	if err := manager.writeOwned(ctx, executionBindingName("init.container"), data); err != nil {
		t.Fatal(err)
	}
	changedContent := content + "# new immutable deployment\n"
	changedDirectory, err := root.PublishBundle(ctx, "changed", []fssecure.BundleFile{{Path: "init.container", Data: []byte(changedContent), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ApplyPublished(ctx, root, changedDirectory, "init.container", changedContent, false); err != nil {
		t.Fatal(err)
	}
	if manager.VerifyPublishedCompletion(ctx, root, changedDirectory, "init.container", changedContent) == nil {
		t.Fatal("unexecuted new publication adopted old success")
	}
	if err := manager.ApplyPublished(ctx, root, changedDirectory, "init.container", changedContent, true); err != nil {
		t.Fatal(err)
	}
	if manager.VerifyPublishedCompletion(ctx, root, changedDirectory, "init.container", changedContent) == nil {
		t.Fatal("new restart adopted earlier native timestamps")
	}
	if err := os.WriteFile(filepath.Join(manager.baseDir, executionBindingName("init.container")), data, 0600); err != nil {
		t.Fatal(err)
	}
	if manager.VerifyPublishedCompletion(ctx, root, changedDirectory, "init.container", changedContent) == nil {
		t.Fatal("altered execution receipt accepted")
	}
}

func TestPublishedActivationPreservesForeignUnitBeforeExecutionReceipt(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PATH", base)
	if err := os.WriteFile(filepath.Join(base, "podman"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	content := "[Container]\nImage=example:fixture\nContainerName=init\nLabel=com.docker.compose.project=owned\nLabel=com.docker.compose.service=init\n"
	root, err := fssecure.OpenRoot(filepath.Join(base, "stage"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := root.PublishBundle(context.Background(), "owned", []fssecure.BundleFile{{Path: "init.container", Data: []byte(content), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	manager, _ := NewManager(filepath.Join(base, "units"))
	if err := os.MkdirAll(manager.baseDir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(manager.baseDir, "init.container")
	if err := os.WriteFile(file, []byte("foreign source"), 0600); err != nil {
		t.Fatal(err)
	}
	if manager.ApplyPublished(context.Background(), root, directory, "init.container", content, true) == nil {
		t.Fatal("foreign source adopted")
	}
	if data, _ := os.ReadFile(file); string(data) != "foreign source" {
		t.Fatal("foreign source changed")
	}
	if _, err := os.Stat(filepath.Join(manager.baseDir, executionBindingName("init.container"))); !os.IsNotExist(err) {
		t.Fatal("foreign source caused execution receipt mutation", err)
	}
}
