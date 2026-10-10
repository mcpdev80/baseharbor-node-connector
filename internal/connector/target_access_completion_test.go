//go:build linux

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/quadlet"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func TestTypedCompletionObservesExactPublicationWithoutAdmissionOrRestart(t *testing.T) {
	base := t.TempDir()
	t.Setenv("PATH", base)
	for name, script := range map[string]string{
		"systemctl": "#!/bin/sh\nif [ \"$2\" = show ]; then printf '%s\\n' \"$BASEHARBOR_TEST_UNIT_STATE\"; else printf '%s\\n' \"$*\" >> \"$BASEHARBOR_TEST_MUTATIONS\"; fi\n",
		"podman":    "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	mutations := filepath.Join(base, "mutations")
	t.Setenv("BASEHARBOR_TEST_MUTATIONS", mutations)
	root, err := fssecure.OpenRoot(filepath.Join(base, "stage"))
	if err != nil {
		t.Fatal(err)
	}
	content := "[Container]\nImage=example:fixture\nContainerName=init\nLabel=com.docker.compose.project=owned\nLabel=com.docker.compose.service=init\n"
	directory, err := root.PublishBundle(context.Background(), "owned", []fssecure.BundleFile{{Path: "init.container", Data: []byte(content), Mode: 0600}})
	if err != nil {
		t.Fatal(err)
	}
	units := filepath.Join(base, "units")
	manager, err := quadlet.NewManager(units)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ApplyPublished(context.Background(), root, directory, "init.container", content, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(units, "init.container.d", "98-baseharbor-execution.json"))
	var binding struct {
		NotBefore uint64 `json:"not_before_micros"`
	}
	if err != nil || json.Unmarshal(data, &binding) != nil || binding.NotBefore == 0 {
		t.Fatal("missing execution binding", err)
	}
	state := fmt.Sprintf("Id=init.service\nLoadState=loaded\nSourcePath=%s\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=1\nExecMainStatus=0\nExecMainStartTimestampMonotonic=%d\nExecMainExitTimestampMonotonic=%d\n", filepath.Join(units, "init.container"), binding.NotBefore+1, binding.NotBefore+2)
	t.Setenv("BASEHARBOR_TEST_UNIT_STATE", state)
	service := &Service{Runtime: bhruntime.Detection{Kind: bhruntime.Podman}, Capabilities: capability.ForRuntime("podman"), Quadlet: manager, Staging: root}
	access, err := service.TargetAccess(targetaccess.NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111", NodeID: "node-a", TargetID: "target-a", Runtime: "podman", Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(mutations)
	for _, scenario := range []string{"success", "nonzero", "wrong-source", "foreign-bundle", "foreign-target"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("BASEHARBOR_TEST_UNIT_STATE", state)
			payload := targetaccess.QuadletCompletionRequest{Name: "init.container", Content: content, ProjectDirectory: directory}
			request := controlRequest("completion-" + scenario)
			request.Operation = targetaccess.OpQuadletCompletion
			request.DeadlineAt = time.Now().UTC().Add(time.Minute)
			switch scenario {
			case "nonzero":
				t.Setenv("BASEHARBOR_TEST_UNIT_STATE", strings.Replace(state, "ExecMainStatus=0", "ExecMainStatus=17", 1))
			case "wrong-source":
				payload.Content += "# changed\n"
			case "foreign-bundle":
				payload.ProjectDirectory = "bundles/.object-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			case "foreign-target":
				request.TargetID = "foreign"
			}
			request.Payload, _ = json.Marshal(payload)
			if err := request.Validate(time.Now()); err != nil {
				wire, _ := json.Marshal(request)
				t.Fatalf("invalid synthetic completion request: %v; wire=%s", err, wire)
			}
			response := access.Execute(context.Background(), request)
			if response.Success != (scenario == "success") {
				t.Fatal("completion admission differs", response.Error)
			}
			if response.Success {
				var result targetaccess.QuadletCompletionResult
				if json.Unmarshal(response.Result, &result) != nil || !result.Completed || result.Name != payload.Name || result.ProjectDirectory != directory || len(result.ContentSHA256) != 64 {
					t.Fatal("completion source binding was lost")
				}
			}
		})
	}
	after, _ := os.ReadFile(mutations)
	if string(before) != string(after) {
		t.Fatal("read-only completion restarted or mutated units")
	}
}
