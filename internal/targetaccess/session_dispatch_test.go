package targetaccess

import (
	"encoding/json"
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestReadInboundFrameClassifiesRequestAndStreamOpen(t *testing.T) {
	request := Request{
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-1",
		CorrelationID: "corr-a",
		TargetID:        "target-a",
		Operation:       OpCapabilities,
		Payload: json.RawMessage("{}"),
		IssuedAt: time.Now().UTC(),
		DeadlineAt: time.Now().UTC().Add(5*time.Minute),
	}
	session := testReadSession(t, request)
	frame, err := session.ReadInboundFrame()
	if err != nil {
		t.Fatal(err)
	}
	if frame.Request == nil || frame.Request.RequestID != request.RequestID || frame.StreamOpen != nil {
		t.Fatalf("unexpected request frame: %#v", frame)
	}

	open := StreamOpen{DeadlineAt: time.Now().UTC().Add(5*time.Minute), CorrelationID: "corr-a",
		ContractVersion: ContractVersion,
		ProtocolVersion: ProtocolVersion,
		StreamID:        "stream-1",
		TargetID:        "target-a",
		ResourceID:      "container-a",
		Kind:            StreamLogs,
		Logs:            &LogStreamOptions{Tail: 100, Follow: true},
	}
	session = testReadSession(t, open)
	frame, err = session.ReadInboundFrame()
	if err != nil {
		t.Fatal(err)
	}
	if frame.StreamOpen == nil || frame.StreamOpen.StreamID != open.StreamID || frame.Request != nil {
		t.Fatalf("unexpected stream frame: %#v", frame)
	}
}

func TestReadInboundFrameRejectsAmbiguousShape(t *testing.T) {
	value := map[string]any{
		"contract_version": ContractVersion,
		"protocol_version": ProtocolVersion,
		"operation":        string(OpCapabilities),
		"kind":             string(StreamLogs),
	}
	session := testReadSession(t, value)
	if _, err := session.ReadInboundFrame(); err == nil {
		t.Fatal("ambiguous inbound frame unexpectedly accepted")
	}
}

func testReadSession(t *testing.T, value any) *Session {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var framed bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	framed.Write(header[:])
	framed.Write(data)
	return &Session{
		reader:   bufio.NewReader(bytes.NewReader(framed.Bytes())),
		maxFrame: DefaultMaxFrameBytes,
		Negotiated: Negotiated{
			ContractVersion: ContractVersion,
			ProtocolVersion: ProtocolVersion,
		},
	}
}
