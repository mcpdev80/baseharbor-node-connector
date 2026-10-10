package compose

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
)

func TestComposePhaseCannotActivateDependenciesOrBuildSource(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PATH", base)
	marker := filepath.Join(base, "calls")
	t.Setenv("BASEHARBOR_TEST_COMPOSE_PHASE_CALLS", marker)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BASEHARBOR_TEST_COMPOSE_PHASE_CALLS\"\nfor arg do\n[ \"$arg\" = config ] && { printf 'sql\\napp\\n'; exit 0; }\ndone\nexit 0\n"
	if err := os.WriteFile(filepath.Join(base, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	root, err := fssecure.OpenRoot(filepath.Join(base, "staging"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := root.PublishBundle(context.Background(), "owned", []fssecure.BundleFile{{Path: "compose.yaml", Data: []byte("services: {sql: {image: postgres}, app: {image: app}}\n")}})
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewAdapter(bhruntime.Docker, root)
	request := ApplyRequest{ProjectDirectory: directory, Files: []string{filepath.Join(directory, "compose.yaml")}, Services: []string{"app"}, ForceRecreate: true}
	if _, err := adapter.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(marker)
	if !strings.Contains(string(calls), "config --services\n") || !strings.Contains(string(calls), "up -d --no-deps --no-build --force-recreate app\n") || strings.Count(string(calls), "up -d") != 1 {
		t.Fatal("phase broadened native activation", string(calls))
	}
	for _, scenario := range []string{"foreign", "duplicate", "flag", "empty", "build", "orphans"} {
		t.Run(scenario, func(t *testing.T) {
			if err := os.WriteFile(marker, nil, 0600); err != nil {
				t.Fatal(err)
			}
			rejected := request
			switch scenario {
			case "foreign":
				rejected.Services = []string{"foreign"}
			case "duplicate":
				rejected.Services = []string{"app", "app"}
			case "flag":
				rejected.Services = []string{"--build"}
			case "empty":
				rejected.Services = []string{}
			case "build":
				rejected.Build = true
			case "orphans":
				rejected.RemoveOrphans = true
			}
			if _, err := adapter.Apply(context.Background(), rejected); err == nil {
				t.Fatal("unsafe phase succeeded")
			}
			calls, _ := os.ReadFile(marker)
			if strings.Contains(string(calls), "up -d") {
				t.Fatal("rejected phase started a service", string(calls))
			}
		})
	}
}
