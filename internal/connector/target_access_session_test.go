package connector

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func TestTargetAccessCapabilitiesOperationReturnsNegotiatedProjection(t *testing.T) {
	service := &Service{
		Runtime:      bhruntime.Detection{Kind: bhruntime.Docker},
		Capabilities: capability.ForRuntime("docker"),
	}
	access, err := service.TargetAccess(targetaccess.NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111",
		NodeID: "node-a", TargetID: "target-a", Runtime: "docker",
		Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	response := access.Execute(context.Background(), targetaccess.Request{
		ContractVersion: targetaccess.ContractVersion,
		ProtocolVersion: targetaccess.ProtocolVersion,
		RequestID:       "req-capabilities",
		CorrelationID:   "corr-a",
		TargetID:        "target-a",
		Operation:       targetaccess.OpCapabilities,
		Payload:         json.RawMessage("{}"),
		IssuedAt:        time.Now().UTC(),
		DeadlineAt:      time.Now().UTC().Add(5 * time.Minute),
	})
	if !response.Success {
		t.Fatalf("capability request failed: %#v", response.Error)
	}
	var set targetaccess.CapabilitySet
	if err := json.Unmarshal(response.Result, &set); err != nil {
		t.Fatal(err)
	}
	if err := set.Validate(); err != nil {
		t.Fatalf("invalid capability response: %v", err)
	}
	if set.Node.NodeID != "node-a" || set.Node.TargetID != "target-a" {
		t.Fatalf("wrong capability node identity: %#v", set.Node)
	}
}
