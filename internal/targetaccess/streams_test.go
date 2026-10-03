package targetaccess

import "testing"

func TestNegotiateRequiresCommonExplicitVersions(t *testing.T) {
	node := NodeIdentity{NodeID: "node-a", TargetID: "target-a", Runtime: "docker", Identity: "node-a.example"}
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
	logs := StreamOpen{
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		StreamID:        "stream-1", TargetID: "target-a", ResourceID: "container-a",
		Kind: StreamLogs, Logs: &LogStreamOptions{Tail: 100, Follow: true},
	}
	if err := logs.Validate(); err != nil {
		t.Fatalf("valid log stream rejected: %v", err)
	}

	terminal := StreamOpen{
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		StreamID:        "stream-2", TargetID: "target-a", ResourceID: "container-a",
		Kind: StreamTerminal, Terminal: &TerminalStreamOptions{},
	}
	if err := terminal.Validate(); err == nil {
		t.Fatal("terminal stream without argv unexpectedly accepted")
	}
}
