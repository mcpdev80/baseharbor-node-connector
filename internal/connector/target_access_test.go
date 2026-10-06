package connector

import (
	"path/filepath"
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func TestTargetAccessCapabilitiesAreBoundToNodeAndRuntime(t *testing.T) {
	service := &Service{TransportStateRoot: filepath.Join(t.TempDir(), "transport"),
		Runtime:      bhruntime.Detection{Kind: bhruntime.Docker, Version: "test"},
		Capabilities: capability.ForRuntime("docker"),
	}
	access, err := service.TargetAccess(targetaccess.NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111",
		NodeID:   "node-a",
		TargetID: "target-a",
		Runtime:  "docker",
		Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	set := access.Capabilities()
	if set.ContractVersion != targetaccess.ContractVersion || set.ProtocolVersion != targetaccess.ProtocolVersion {
		t.Fatalf("unexpected versions: %#v", set)
	}
	if set.Node.TargetID != "target-a" || set.Node.NodeID != "node-a" {
		t.Fatalf("unexpected node identity: %#v", set.Node)
	}
	for _, descriptor := range set.Capabilities {
		switch descriptor.Name {
		case capability.QuadletApply, capability.QuadletRemove, capability.QuadletEnable, capability.QuadletDisable:
			if descriptor.Available {
				t.Fatalf("docker advertised Podman-only capability %q", descriptor.Name)
			}
		}
	}
}

func TestTargetAccessRejectsRuntimeIdentityMismatch(t *testing.T) {
	service := &Service{TransportStateRoot: filepath.Join(t.TempDir(), "transport"),
		Runtime:      bhruntime.Detection{Kind: bhruntime.Docker},
		Capabilities: capability.ForRuntime("docker"),
	}
	_, err := service.TargetAccess(targetaccess.NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111",
		NodeID: "node-a", TargetID: "target-a", Runtime: "podman",
		Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a",
	})
	if err == nil {
		t.Fatal("runtime identity mismatch unexpectedly accepted")
	}
}

func TestTargetAccessOperationAvailabilityUsesNegotiatedCapabilities(t *testing.T) {
	service := &Service{TransportStateRoot: filepath.Join(t.TempDir(), "transport"),
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
	if !access.operationAvailable(targetaccess.OpContainerRestart) {
		t.Fatal("container restart capability unexpectedly unavailable")
	}
	if access.operationAvailable(targetaccess.OpQuadletEnable) {
		t.Fatal("Podman-only Quadlet capability unexpectedly available on Docker")
	}
	if access.operationAvailable(targetaccess.Operation("runtime_command")) {
		t.Fatal("generic runtime command unexpectedly available")
	}
}
