package targetaccess

import (
	"testing"
	"time"
)

func TestNegotiateRequiresCommonExplicitVersions(t *testing.T) {
	node := NodeIdentity{TenantID: "11111111-1111-4111-8111-111111111111",NodeID: "node-a", TargetID: "target-a", Runtime: "docker", Identity: "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/target-a/node-a"}
	local := Hello{ContractVersions: []string{ContractVersion}, ProtocolVersions: []string{ProtocolVersion}, Node: node}
	remote := local
	negotiated, err := Negotiate(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if negotiated.ContractVersion != ContractVersion || negotiated.ProtocolVersion != ProtocolVersion {
		t.Fatalf("unexpected negotiation: %#v", negotiated)
	}

	remote.ProtocolVersions = []string{"999"}
	if _, err := Negotiate(local, remote); err == nil {
		t.Fatal("incompatible protocol unexpectedly negotiated")
	}
}

func TestStreamOpenIsTypedAndRejectsTerminalWithoutArgv(t *testing.T) {
	logs := StreamOpen{DeadlineAt: time.Now().UTC().Add(5*time.Minute), CorrelationID: "corr-a",
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		StreamID:        "stream-1", TargetID: "target-a", ResourceID: "container-a",
		Kind: StreamLogs, Logs: &LogStreamOptions{Tail: 100, Follow: true},
	}
	if err := logs.Validate(); err != nil {
		t.Fatalf("valid log stream rejected: %v", err)
	}

	terminal := StreamOpen{DeadlineAt: time.Now().UTC().Add(5*time.Minute), CorrelationID: "corr-a",
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		StreamID:        "stream-2", TargetID: "target-a", ResourceID: "container-a",
		Kind: StreamTerminal, Terminal: &TerminalStreamOptions{Rows:24, Cols:80},
	}
	if err := terminal.Validate(); err == nil {
		t.Fatal("terminal stream without argv unexpectedly accepted")
	}
}
