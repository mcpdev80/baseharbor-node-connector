package connector

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/container"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func (a *TargetAccess) ServeLogStream(ctx context.Context, session *targetaccess.Session, open targetaccess.StreamOpen) error {
	if a == nil {
		return errors.New("target access service is required")
	}
	if session == nil {
		return errors.New("target access session is required")
	}
	if err := open.Validate(); err != nil {
		return err
	}
	if open.Kind != targetaccess.StreamLogs {
		return errors.New("stream is not a log stream")
	}
	if open.TargetID != a.identity.TargetID {
		return errors.New("stream target does not match connector target identity")
	}
	if !a.capabilityAvailable(capability.LogRead) {
		return errors.New("log streaming capability is unavailable")
	}
	if open.ResumeAfter != 0 {
		return errors.New("log stream replay is not implemented; resume_after must be zero")
	}

	reader, err := a.service.Observation.LogStream(ctx, open.ResourceID, container.LogOptions{
		Tail: open.Logs.Tail,
		Since: open.Logs.Since,
	}, open.Logs.Follow)
	if err != nil {
		return err
	}
	defer reader.Close()

	sequence := uint64(1)
	if err := session.WriteStreamEvent(streamEvent(open, sequence, targetaccess.StreamReady, nil, "")); err != nil {
		return err
	}
	sequence++

	buffer := make([]byte, 32*1024)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			data := append([]byte(nil), buffer[:n]...)
			if err := session.WriteStreamEvent(streamEvent(open, sequence, targetaccess.StreamData, data, "")); err != nil {
				return err
			}
			sequence++
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return session.WriteStreamEvent(streamEvent(open, sequence, targetaccess.StreamEnd, nil, ""))
			}
			_ = session.WriteStreamEvent(streamEvent(open, sequence, targetaccess.StreamError, nil, readErr.Error()))
			return readErr
		}
		select {
		case <-ctx.Done():
			_ = session.WriteStreamEvent(streamEvent(open, sequence, targetaccess.StreamEnd, nil, ctx.Err().Error()))
			return ctx.Err()
		default:
		}
	}
}

func (a *TargetAccess) capabilityAvailable(name capability.Name) bool {
	for _, descriptor := range a.service.Capabilities {
		if descriptor.Name == name {
			return descriptor.Available
		}
	}
	return false
}

func streamEvent(open targetaccess.StreamOpen, sequence uint64, kind targetaccess.StreamEventType, data []byte, message string) targetaccess.StreamEvent {
	return targetaccess.StreamEvent{
		ContractVersion: targetaccess.ContractVersion,
		ProtocolVersion: targetaccess.ProtocolVersion,
		StreamID: open.StreamID,
		CorrelationID: open.CorrelationID,
		Sequence: sequence,
		ObservedAt: time.Now().UTC(),
		Type: kind,
		Data: data,
		Message: message,
	}
}
