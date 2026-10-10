package connector

import (
	"errors"
	"sync"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

const defaultStreamReplayEvents = 512

type streamReplayRegistry struct {
	mu      sync.RWMutex
	max     int
	streams map[string]*streamReplay
}

type streamReplay struct {
	events   []targetaccess.StreamEvent
	terminal bool
	active   bool
	closed   bool
}

func newStreamReplayRegistry(maxEvents int) *streamReplayRegistry {
	if maxEvents <= 0 {
		maxEvents = defaultStreamReplayEvents
	}
	return &streamReplayRegistry{
		max:     maxEvents,
		streams: map[string]*streamReplay{},
	}
}

func (r *streamReplayRegistry) begin(streamID string, terminal bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.streams[streamID]; ok && !existing.closed {
		return errors.New("stream_id is already active")
	}
	r.streams[streamID] = &streamReplay{terminal: terminal, active: true}
	return nil
}

func (r *streamReplayRegistry) append(event targetaccess.StreamEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stream, ok := r.streams[event.StreamID]
	if !ok {
		stream = &streamReplay{}
		r.streams[event.StreamID] = stream
	}
	stream.events = append(stream.events, event)
	if len(stream.events) > r.max {
		stream.events = append([]targetaccess.StreamEvent(nil), stream.events[len(stream.events)-r.max:]...)
	}
	switch event.Type {
	case targetaccess.StreamExit, targetaccess.StreamEnd, targetaccess.StreamError:
		stream.closed = true
		stream.active = false
	}
}

func (r *streamReplayRegistry) resume(streamID string, after uint64) ([]targetaccess.StreamEvent, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stream, ok := r.streams[streamID]
	if !ok {
		return nil, false, errors.New("stream replay state was not found")
	}
	if stream.terminal {
		return nil, false, errors.New("terminal sessions cannot be resumed or replayed")
	}
	if stream.active && !stream.closed {
		return nil, false, errors.New("stream is still attached to another transport")
	}
	if after > 0 && len(stream.events) > 0 {
		first := stream.events[0].Sequence
		if after+1 < first {
			return nil, stream.closed, errors.New("requested resume cursor is older than retained stream history")
		}
	}
	var result []targetaccess.StreamEvent
	for _, event := range stream.events {
		if event.Sequence > after {
			result = append(result, event)
		}
	}
	if !stream.closed {
		stream.active = true
	}
	return result, stream.closed, nil
}

func (r *streamReplayRegistry) detach(streamID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if stream, ok := r.streams[streamID]; ok && !stream.closed {
		stream.active = false
	}
}

func (r *streamReplayRegistry) replay(streamID string, after uint64) ([]targetaccess.StreamEvent, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	stream, ok := r.streams[streamID]
	if !ok {
		return nil, false, errors.New("stream replay state was not found")
	}
	if after > 0 && len(stream.events) > 0 {
		first := stream.events[0].Sequence
		if after+1 < first {
			return nil, stream.closed, errors.New("requested resume cursor is older than retained stream history")
		}
	}
	var result []targetaccess.StreamEvent
	for _, event := range stream.events {
		if event.Sequence > after {
			result = append(result, event)
		}
	}
	return result, stream.closed, nil
}

func (r *streamReplayRegistry) lastSequence(streamID string) uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	stream, ok := r.streams[streamID]
	if !ok || len(stream.events) == 0 {
		return 0
	}
	return stream.events[len(stream.events)-1].Sequence
}

func (r *streamReplayRegistry) lastObserved(streamID string) time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	stream, ok := r.streams[streamID]
	if !ok || len(stream.events) == 0 {
		return time.Time{}
	}
	return stream.events[len(stream.events)-1].ObservedAt
}
