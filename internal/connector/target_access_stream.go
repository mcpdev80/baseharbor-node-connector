package connector

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/container"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func (a *TargetAccess) ServeStream(ctx context.Context, session *targetaccess.Session) error {
	if a == nil {
		return errors.New("target access service is required")
	}
	if session == nil {
		return errors.New("target access session is required")
	}
	var open targetaccess.StreamOpen
	if err := session.ReadStreamOpen(&open); err != nil {
		return err
	}
	switch open.Kind {
	case targetaccess.StreamLogs:
		return a.ServeLogStream(ctx, session, open)
	case targetaccess.StreamTerminal:
		return a.ServeTerminalStream(ctx, session, open)
	default:
		return errors.New("unsupported target access stream kind")
	}
}

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
	if !open.DeadlineAt.After(time.Now()) || open.DeadlineAt.After(time.Now().Add(5*time.Minute)) {
		return targetaccess.ErrTargetAccessWire
	}
	ctx, cancel := context.WithDeadline(ctx, open.DeadlineAt)
	defer cancel()
	defer session.Close()
	if open.Kind != targetaccess.StreamLogs {
		return errors.New("stream is not a log stream")
	}
	if open.TargetID != a.identity.TargetID {
		return errors.New("stream target does not match connector target identity")
	}
	if !a.capabilityAvailable(capability.LogRead) {
		return errors.New("log streaming capability is unavailable")
	}

	sequence := uint64(1)
	since := open.Logs.Since
	if open.ResumeAfter == 0 {
		if err := a.streams.begin(open.StreamID, false); err != nil {
			return err
		}
	} else {
		events, closed, err := a.streams.resume(open.StreamID, open.ResumeAfter)
		if err != nil {
			return err
		}
		for _, event := range events {
			if err := session.WriteStreamEvent(event); err != nil {
				a.streams.detach(open.StreamID)
				return err
			}
		}
		if closed {
			return nil
		}
		sequence = a.streams.lastSequence(open.StreamID) + 1
		if observed := a.streams.lastObserved(open.StreamID); !observed.IsZero() {
			overlap := observed.Add(-5 * time.Second).UTC().Format(time.RFC3339Nano)
			if strings.TrimSpace(since) == "" {
				since = overlap
			} else if parsed, err := time.Parse(time.RFC3339Nano, since); err == nil && parsed.After(observed.Add(-5*time.Second)) {
				since = overlap
			}
		}
	}
	defer func() {
		a.streams.detach(open.StreamID)
	}()

	reader, err := a.service.Observation.LogStream(ctx, open.ResourceID, container.LogOptions{
		Tail:  open.Logs.Tail,
		Since: since,
	}, open.Logs.Follow)
	if err != nil {
		a.streams.detach(open.StreamID)
		return err
	}
	defer reader.Close()

	send := func(event targetaccess.StreamEvent) error {
		a.streams.append(event)
		if err := session.WriteStreamEvent(event); err != nil {
			a.streams.detach(open.StreamID)
			return err
		}
		return nil
	}

	if open.ResumeAfter == 0 {
		if err := send(streamEvent(open, sequence, targetaccess.StreamReady, nil, "")); err != nil {
			return err
		}
		sequence++
	}

	buffer := make([]byte, targetaccess.TargetAccessMaxStreamDataBytes)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			data := append([]byte(nil), buffer[:n]...)
			if err := send(streamEvent(open, sequence, targetaccess.StreamData, data, "")); err != nil {
				return err
			}
			sequence++
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				event := streamEvent(open, sequence, targetaccess.StreamEnd, nil, "")
				return send(event)
			}
			event := streamEvent(open, sequence, targetaccess.StreamError, nil, "The runtime stream failed.")
			_ = send(event)
			return readErr
		}
		select {
		case <-ctx.Done():
			event := streamEvent(open, sequence, targetaccess.StreamEnd, nil, "")
			_ = send(event)
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
		StreamID:        open.StreamID,
		CorrelationID:   open.CorrelationID,
		Sequence:        sequence,
		ObservedAt:      time.Now().UTC(),
		Type:            kind,
		Data:            data,
		Message:         message,
	}
}

func (a *TargetAccess) ServeTerminalStream(ctx context.Context, session *targetaccess.Session, open targetaccess.StreamOpen) error {
	if a == nil {
		return errors.New("target access service is required")
	}
	if session == nil {
		return errors.New("target access session is required")
	}
	if err := open.Validate(); err != nil {
		return err
	}
	if !open.DeadlineAt.After(time.Now()) || open.DeadlineAt.After(time.Now().Add(5*time.Minute)) {
		return targetaccess.ErrTargetAccessWire
	}
	ctx, cancel := context.WithDeadline(ctx, open.DeadlineAt)
	defer cancel()
	defer session.Close()
	if open.Kind != targetaccess.StreamTerminal {
		return errors.New("stream is not a terminal stream")
	}
	if open.TargetID != a.identity.TargetID {
		return errors.New("stream target does not match connector target identity")
	}
	if !a.capabilityAvailable(capability.Terminal) {
		return errors.New("terminal streaming capability is unavailable")
	}
	if open.ResumeAfter != 0 {
		return errors.New("terminal stream replay is not implemented; resume_after must be zero")
	}

	terminal, err := a.service.Observation.StartTerminal(ctx, open.ResourceID, container.TerminalRequest{
		Argv:        append([]string(nil), open.Terminal.Argv...),
		Workdir:     open.Terminal.Workdir,
		User:        open.Terminal.User,
		Environment: copyStringMap(open.Terminal.Environment),
		Rows:        uint16(open.Terminal.Rows),
		Cols:        uint16(open.Terminal.Cols),
	})
	if err != nil {
		return err
	}
	defer terminal.Close()

	sequence := uint64(1)
	if err := session.WriteStreamEvent(streamEvent(open, sequence, targetaccess.StreamReady, nil, "")); err != nil {
		return err
	}
	sequence++

	inputErr := make(chan error, 1)
	go func() {
		expectedSequence := uint64(1)
		for {
			var event targetaccess.StreamEvent
			if err := session.ReadStreamEvent(&event); err != nil {
				_ = terminal.Close()
				inputErr <- err
				return
			}
			if event.StreamID != open.StreamID || event.CorrelationID != open.CorrelationID || event.Sequence != expectedSequence {
				_ = terminal.Close()
				inputErr <- errors.New("terminal input scope or sequence mismatch")
				return
			}
			expectedSequence++
			switch event.Type {
			case targetaccess.StreamData:
				if len(event.Data) > 0 {
					if _, err := terminal.Write(event.Data); err != nil {
						inputErr <- err
						return
					}
				}
			case targetaccess.StreamResize:
				if event.Rows <= 0 || event.Cols <= 0 || event.Rows > 512 || event.Cols > 512 {
					inputErr <- errors.New("invalid terminal resize dimensions")
					return
				}
				if err := terminal.Resize(uint16(event.Rows), uint16(event.Cols)); err != nil {
					inputErr <- err
					return
				}
			case targetaccess.StreamEnd:
				_ = terminal.Close()
				inputErr <- io.EOF
				return
			default:
				_ = terminal.Close()
				inputErr <- errors.New("unsupported terminal input event")
				return
			}
		}
	}()

	waitResult := make(chan terminalWaitResult, 1)
	go func() {
		exitCode, err := terminal.Wait()
		waitResult <- terminalWaitResult{exitCode: exitCode, err: err}
	}()

	var writeMu sync.Mutex
	send := func(event targetaccess.StreamEvent) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return session.WriteStreamEvent(event)
	}

	buffer := make([]byte, targetaccess.TargetAccessMaxStreamDataBytes)
	for {
		n, readErr := terminal.Read(buffer)
		if n > 0 {
			data := append([]byte(nil), buffer[:n]...)
			if err := send(streamEvent(open, sequence, targetaccess.StreamData, data, "")); err != nil {
				return err
			}
			sequence++
		}

		select {
		case err := <-inputErr:
			if err != nil && !errors.Is(err, io.EOF) {
				_ = send(streamEvent(open, sequence, targetaccess.StreamError, nil, "Terminal input failed."))
				return err
			}
			_ = terminal.Close()
		default:
		}

		select {
		case result := <-waitResult:
			event := streamEvent(open, sequence, targetaccess.StreamExit, nil, "")
			event.ExitCode = &result.exitCode
			if result.err != nil && result.exitCode == 0 {
				event.ExitCode = new(int)
				*event.ExitCode = -1
			}
			return send(event)
		default:
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				select {
				case result := <-waitResult:
					event := streamEvent(open, sequence, targetaccess.StreamExit, nil, "")
					event.ExitCode = &result.exitCode
					if result.err != nil && result.exitCode == 0 {
						event.ExitCode = new(int)
						*event.ExitCode = -1
					}
					return send(event)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			_ = send(streamEvent(open, sequence, targetaccess.StreamError, nil, "The runtime stream failed."))
			return readErr
		}

		select {
		case <-ctx.Done():
			_ = send(streamEvent(open, sequence, targetaccess.StreamEnd, nil, ""))
			return ctx.Err()
		default:
		}
	}
}

type terminalWaitResult struct {
	exitCode int
	err      error
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
