package connector

import (
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func TestStreamReplayRegistryReplaysAfterCursorAndBoundsHistory(t *testing.T) {
	registry := newStreamReplayRegistry(3)
	if err := registry.begin("stream-a", false); err != nil {
		t.Fatal(err)
	}
	for sequence := uint64(1); sequence <= 5; sequence++ {
		registry.append(targetaccess.StreamEvent{
			ContractVersion: targetaccess.ContractVersion,
			ProtocolVersion: targetaccess.ProtocolVersion,
			StreamID: "stream-a",
			Sequence: sequence,
			ObservedAt: time.Now().UTC(),
			Type: targetaccess.StreamData,
		})
	}
	events, closed, err := registry.replay("stream-a", 3)
	if err != nil {
		t.Fatal(err)
	}
	if closed {
		t.Fatal("active stream unexpectedly closed")
	}
	if len(events) != 2 || events[0].Sequence != 4 || events[1].Sequence != 5 {
		t.Fatalf("unexpected replay: %#v", events)
	}
	if _, _, err := registry.replay("stream-a", 1); err == nil {
		t.Fatal("expired replay cursor unexpectedly accepted")
	}
}

func TestStreamReplayRegistryMarksTerminalEventsClosed(t *testing.T) {
	registry := newStreamReplayRegistry(10)
	if err := registry.begin("stream-a", false); err != nil {
		t.Fatal(err)
	}
	registry.append(targetaccess.StreamEvent{
		ContractVersion: targetaccess.ContractVersion,
		ProtocolVersion: targetaccess.ProtocolVersion,
		StreamID: "stream-a",
		Sequence: 1,
		ObservedAt: time.Now().UTC(),
		Type: targetaccess.StreamEnd,
	})
	events, closed, err := registry.replay("stream-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !closed || len(events) != 1 {
		t.Fatalf("unexpected closed replay state: closed=%v events=%#v", closed, events)
	}
}
