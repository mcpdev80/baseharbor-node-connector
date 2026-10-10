package quadlet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedUnitRemovalPreservesReplacedForeignNativeResource(t *testing.T) {
	for unit, content := range map[string]string{
		"owned.volume":    "[Volume]\nVolumeName=owned-data\nLabel=com.docker.compose.project=project\n",
		"owned.network":   "[Network]\nNetworkName=owned-network\nLabel=com.docker.compose.project=project\n",
		"owned.container": "[Container]\nContainerName=owned\nLabel=com.docker.compose.project=project\nLabel=com.docker.compose.service=workload\n",
	} {
		t.Run(unit, func(t *testing.T) { checkForeignNativeRemoval(t, unit, content) })
	}
}

func checkForeignNativeRemoval(t *testing.T, unit, content string) {
	t.Helper()
	base := t.TempDir()
	marker := filepath.Join(base, "systemctl-calls")
	t.Setenv("BASEHARBOR_TEST_NATIVE_EXISTS", filepath.Join(base, "native-exists"))
	t.Setenv("BASEHARBOR_TEST_NATIVE_INSPECT", `[{"Labels":{"com.docker.compose.project":"foreign"},"Config":{"Labels":{"com.docker.compose.project":"foreign","com.docker.compose.service":"workload"}}}]`)
	t.Setenv("BASEHARBOR_TEST_SYSTEMCTL_CALLS", marker)
	t.Setenv("PATH", base)
	for name, script := range map[string]string{
		"podman":    "#!/bin/sh\ncase \"$2\" in\nexists) [ -f \"$BASEHARBOR_TEST_NATIVE_EXISTS\" ] && exit 0; exit 1;;\ninspect) printf '%s\\n' \"$BASEHARBOR_TEST_NATIVE_INSPECT\"; exit 0;;\nesac\nexit 2\n",
		"systemctl": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BASEHARBOR_TEST_SYSTEMCTL_CALLS\"\n",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	manager, _ := NewManager(filepath.Join(base, "units"))
	if err := manager.Apply(context.Background(), unit, content, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("BASEHARBOR_TEST_NATIVE_EXISTS"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Remove(context.Background(), unit); err == nil {
		t.Fatal("foreign native resource authorized by stale owned unit")
	}
	if calls, err := os.ReadFile(marker); err != nil || len(calls) != 0 {
		t.Fatal("rejected removal stopped a unit", string(calls), err)
	}
	if data, err := os.ReadFile(filepath.Join(manager.baseDir, unit)); err != nil || string(data) != content {
		t.Fatal("foreign replacement changed the protected unit", err)
	}
}
