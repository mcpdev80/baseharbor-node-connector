package targetaccess

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRequestValidationRejectsGenericCommandAndStaleRequests(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	valid := Request{
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-1",
		CorrelationID:   "corr-1",
		TargetID:        "target-a",
		Operation:       OpContainerRestart,
		IssuedAt:        now,
		Payload:         json.RawMessage("{\"resource_id\":\"container-1\"}"),
	}
	if err := valid.Validate(now); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	invalid := valid
	invalid.Operation = Operation("runtime_command")
	if err := invalid.Validate(now); err == nil {
		t.Fatal("generic runtime command unexpectedly accepted")
	}

	stale := valid
	stale.IssuedAt = now.Add(-10 * time.Minute)
	if err := stale.Validate(now); err == nil {
		t.Fatal("stale request unexpectedly accepted")
	}
}

func TestCapabilitySetRequiresExactContractVersionsAndNodeIdentity(t *testing.T) {
	set := CapabilitySet{
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		Node: NodeIdentity{
			NodeID: "node-a", TargetID: "target-a", Runtime: "docker",
			Identity: "spiffe://baseharbor/node/node-a",
		},
	}
	if err := set.Validate(); err != nil {
		t.Fatalf("valid capability set rejected: %v", err)
	}
	set.ProtocolVersion = "2"
	if err := set.Validate(); err == nil {
		t.Fatal("unsupported protocol version unexpectedly accepted")
	}
}
