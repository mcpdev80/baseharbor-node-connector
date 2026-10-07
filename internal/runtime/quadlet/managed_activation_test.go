//go:build linux

package quadlet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishedManagedStartsWithoutBootActivation(t *testing.T) {
	base := t.TempDir()
	log := filepath.Join(base, "commands")
	t.Setenv("BASEHARBOR_TEST_COMMAND_LOG", log)
	t.Setenv("PATH", base)
	for name, script := range map[string]string{
		"systemctl": "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BASEHARBOR_TEST_COMMAND_LOG\"\n",
		"podman":    "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	content := "[Container]\nImage=example:fixture\nContainerName=owned\nLabel=com.docker.compose.project=owned\nLabel=com.docker.compose.service=app\n[Install]\nWantedBy=default.target\nRequiredBy=default.target\nUpheldBy=default.target\nAlias=owned-alias.service\n"
	root, directory := publishedFixture(t, content, 0600)
	manager, err := NewManager(filepath.Join(base, "units"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ApplyPublishedManaged(context.Background(), root, directory, "owned.container", content, true); err != nil {
		t.Fatal(err)
	}
	activation, err := os.ReadFile(filepath.Join(manager.baseDir, "owned.container.d", "99-baseharbor-activation.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(activation), "default.target") || strings.Contains(string(activation), "owned-alias") {
		t.Fatal("managed source still autoactivates", string(activation))
	}
	for _, reset := range []string{"WantedBy=\n", "RequiredBy=\n", "UpheldBy=\n", "Alias=\n"} {
		if !strings.Contains(string(activation), reset) {
			t.Fatal("activation was not cleared", reset)
		}
	}
	commands, err := os.ReadFile(log)
	if err != nil || strings.Count(string(commands), "--user restart owned.service") != 1 {
		t.Fatal("explicit start missing or replayed", err, string(commands))
	}
	if _, err := os.Stat(filepath.Join(manager.baseDir, executionBindingName("owned.container"))); err != nil {
		t.Fatal("managed start lacks protected execution binding", err)
	}
}
