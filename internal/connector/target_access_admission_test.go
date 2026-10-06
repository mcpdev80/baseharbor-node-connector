//go:build linux

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/container"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func TestRuntimeInvocationIsNotRepeatedAfterFailureAndConnectorRestart(t *testing.T) {
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	witness := filepath.Join(fixture, "invocations")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$BASEHARBOR_TEST_INVOCATION_WITNESS"
exit 7
`
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BASEHARBOR_TEST_INVOCATION_WITNESS", witness)
	identity := targetaccess.NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111", NodeID: "node-a", TargetID: "target-a", Runtime: "docker", Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"}
	service := &Service{Runtime: bhruntime.Detection{Kind: bhruntime.Docker}, Capabilities: capability.ForRuntime("docker"), Realizer: container.NewLifecycle(bhruntime.Docker), TransportStateRoot: filepath.Join(fixture, "transport")}
	access, err := service.TargetAccess(identity)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	request := targetaccess.Request{ContractVersion: targetaccess.ContractVersion, ProtocolVersion: targetaccess.ProtocolVersion, RequestID: "failed-operation-a", CorrelationID: "execution-a", TargetID: "target-a", Operation: targetaccess.OpContainerStop, IssuedAt: now, DeadlineAt: now.Add(time.Minute), Payload: json.RawMessage(`{"resource_id":"owned-a"}`)}
	first := access.Execute(context.Background(), request)
	if first.Success || first.Error == nil || first.Error.Code != "operation_failed" {
		t.Fatalf("failed runtime reported success: %#v", first)
	}
	if err := access.Close(); err != nil {
		t.Fatal(err)
	}
	access, err = service.TargetAccess(identity)
	if err != nil {
		t.Fatal(err)
	}
	defer access.Close()
	replay := access.Execute(context.Background(), request)
	if replay.Success || replay.Error == nil || replay.Error.Code != "replay_ambiguous" {
		t.Fatalf("lost/failed result retried: %#v", replay)
	}
	request.Payload = json.RawMessage(`{"resource_id":"foreign-a"}`)
	conflict := access.Execute(context.Background(), request)
	if conflict.Success || conflict.Error == nil || conflict.Error.Code != "replay_conflict" {
		t.Fatalf("changed request retried: %#v", conflict)
	}
	data, err := os.ReadFile(witness)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "stop owned-a" {
		t.Fatalf("runtime was invoked more than once: %q", data)
	}
}

func TestMissingJournalDoesNotAdvertiseOrAdmitMutatingCapabilities(t *testing.T) {
	identity := targetaccess.NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111", NodeID: "node-a", TargetID: "target-a", Runtime: "docker", Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"}
	service := &Service{Runtime: bhruntime.Detection{Kind: bhruntime.Docker}, Capabilities: capability.ForRuntime("docker")}
	access, err := service.TargetAccess(identity)
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range access.Capabilities().Capabilities {
		if targetaccess.RequiresAdmission(targetaccess.Operation(descriptor.Name)) && descriptor.Available {
			t.Fatalf("unavailable persistent admission was advertised: %s", descriptor.Name)
		}
	}
}
