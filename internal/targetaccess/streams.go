package targetaccess

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type StreamKind string

const (
	StreamLogs     StreamKind = "logs"
	StreamTerminal StreamKind = "terminal"
)

type StreamOpen struct {
	ContractVersion string                 `json:"contract_version"`
	ProtocolVersion string                 `json:"protocol_version"`
	StreamID        string                 `json:"stream_id"`
	CorrelationID   string                 `json:"correlation_id,omitempty"`
	TargetID        string                 `json:"target_id"`
	ResourceID      string                 `json:"resource_id"`
	Kind            StreamKind             `json:"kind"`
	ResumeAfter     uint64                 `json:"resume_after,omitempty"`
	Logs            *LogStreamOptions      `json:"logs,omitempty"`
	Terminal        *TerminalStreamOptions `json:"terminal,omitempty"`
}

type LogStreamOptions struct {
	Tail   int    `json:"tail,omitempty"`
	Since  string `json:"since,omitempty"`
	Follow bool   `json:"follow,omitempty"`
}

type TerminalStreamOptions struct {
	Rows        int               `json:"rows,omitempty"`
	Cols        int               `json:"cols,omitempty"`
	User        string            `json:"user,omitempty"`
	Workdir     string            `json:"workdir,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Argv        []string          `json:"argv"`
}

func (o StreamOpen) Validate() error {
	if o.ContractVersion != ContractVersion || o.ProtocolVersion != ProtocolVersion {
		return errors.New("unsupported stream contract/protocol version")
	}
	for name, value := range map[string]string{
		"stream_id":   o.StreamID,
		"target_id":   o.TargetID,
		"resource_id": o.ResourceID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	switch o.Kind {
	case StreamLogs:
		if o.Logs == nil || o.Terminal != nil {
			return errors.New("logs stream requires only logs options")
		}
		if o.Logs.Tail < 0 {
			return errors.New("logs tail must not be negative")
		}
	case StreamTerminal:
		if o.Terminal == nil || o.Logs != nil {
			return errors.New("terminal stream requires only terminal options")
		}
		if len(o.Terminal.Argv) == 0 {
			return errors.New("terminal argv is required")
		}
		for _, arg := range o.Terminal.Argv {
			if strings.ContainsRune(arg, '\x00') {
				return errors.New("terminal argv contains NUL")
			}
		}
	default:
		return fmt.Errorf("unsupported stream kind %q", o.Kind)
	}
	return nil
}

type StreamEventType string

const (
	StreamReady  StreamEventType = "ready"
	StreamData   StreamEventType = "data"
	StreamResize StreamEventType = "resize"
	StreamExit   StreamEventType = "exit"
	StreamError  StreamEventType = "error"
	StreamEnd    StreamEventType = "end"
)

type StreamEvent struct {
	ContractVersion string          `json:"contract_version"`
	ProtocolVersion string          `json:"protocol_version"`
	StreamID        string          `json:"stream_id"`
	CorrelationID   string          `json:"correlation_id,omitempty"`
	Sequence        uint64          `json:"sequence"`
	ObservedAt      time.Time       `json:"observed_at"`
	Type            StreamEventType `json:"type"`
	Data            []byte          `json:"data,omitempty"`
	Rows            int             `json:"rows,omitempty"`
	Cols            int             `json:"cols,omitempty"`
	ExitCode        *int            `json:"exit_code,omitempty"`
	Message         string          `json:"message,omitempty"`
}

func (e StreamEvent) Validate() error {
	if e.ContractVersion != ContractVersion || e.ProtocolVersion != ProtocolVersion {
		return errors.New("unsupported stream event version")
	}
	if strings.TrimSpace(e.StreamID) == "" {
		return errors.New("stream_id is required")
	}
	if e.Sequence == 0 {
		return errors.New("stream event sequence starts at 1")
	}
	if e.ObservedAt.IsZero() {
		return errors.New("observed_at is required")
	}
	switch e.Type {
	case StreamReady, StreamData, StreamResize, StreamExit, StreamError, StreamEnd:
		return nil
	default:
		return fmt.Errorf("unsupported stream event type %q", e.Type)
	}
}

type ResumeState struct {
	StreamID     string `json:"stream_id"`
	LastSequence uint64 `json:"last_sequence"`
}

func (r ResumeState) Validate() error {
	if strings.TrimSpace(r.StreamID) == "" {
		return errors.New("stream_id is required")
	}
	return nil
}
