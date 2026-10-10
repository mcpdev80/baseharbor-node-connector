package quadlet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedNetworkRemovalPreservesLiveConsumersAndReconcilesExplicitRetry(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PATH", base)
	t.Setenv("BASEHARBOR_TEST_NETWORK_EXISTS", filepath.Join(base, "network"))
	t.Setenv("BASEHARBOR_TEST_NETWORK_CALLS", filepath.Join(base, "calls"))
	t.Setenv("BASEHARBOR_TEST_NETWORK_IN_USE", "yes")
	for name, script := range map[string]string{
		"systemctl": "#!/bin/sh\nexit 0\n",
		"podman":    "#!/bin/sh\ncase \"$2\" in\nexists) [ -f \"$BASEHARBOR_TEST_NETWORK_EXISTS\" ] && exit 0; exit 1;;\ninspect) printf '%s\\n' '[{\"Labels\":{\"com.docker.compose.project\":\"owned\"}}]'; exit 0;;\nrm) printf '%s\\n' \"$*\" >> \"$BASEHARBOR_TEST_NETWORK_CALLS\"; [ \"$BASEHARBOR_TEST_NETWORK_IN_USE\" = yes ] && exit 2; /bin/rm \"$BASEHARBOR_TEST_NETWORK_EXISTS\"; exit 0;;\nesac\nexit 2\n",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := NewManager(filepath.Join(base, "units"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	content := "[Network]\nNetworkName=owned-net\nLabel=com.docker.compose.project=owned\n"
	if err := manager.Apply(ctx, "owned.network", content, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("BASEHARBOR_TEST_NETWORK_EXISTS"), []byte("live consumer"), 0600); err != nil {
		t.Fatal(err)
	}
	if manager.Remove(ctx, "owned.network") == nil {
		t.Fatal("in-use network removal succeeded")
	}
	for _, path := range []string{os.Getenv("BASEHARBOR_TEST_NETWORK_EXISTS"), filepath.Join(manager.baseDir, "owned.network")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("failed removal lost network or protected retry source", err)
		}
	}
	t.Setenv("BASEHARBOR_TEST_NETWORK_IN_USE", "no")
	if err := manager.Remove(ctx, "owned.network"); err != nil {
		t.Fatal("explicit retry failed", err)
	}
	if _, err := os.Stat(os.Getenv("BASEHARBOR_TEST_NETWORK_EXISTS")); !os.IsNotExist(err) {
		t.Fatal("owned network survived successful removal")
	}
	calls, err := os.ReadFile(os.Getenv("BASEHARBOR_TEST_NETWORK_CALLS"))
	if err != nil || strings.Contains(string(calls), "-f") || strings.Count(string(calls), "network rm owned-net") != 2 {
		t.Fatal("network removal forced or automatically replayed mutation", string(calls), err)
	}
}
