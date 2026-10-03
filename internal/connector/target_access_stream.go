package connector

import (
	"context"
	"errors"
	"io"
	"sync"
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
		for {
			var event targetaccess.StreamEvent
			if err := session.ReadStreamEvent(&event); err != nil {
				inputErr <- err
				return
			}
			if event.StreamID != open.StreamID {
				inputErr <- errors.New("terminal input event stream_id mismatch")
				return
			}
			switch event.Type {
			case targetaccess.StreamData:
				if len(event.Data) > 0 {
					if _, err := terminal.Write(event.Data); err != nil {
						inputErr <- err
						return
					}
				}
			case targetaccess.StreamResize:
				if event.Rows <= 0 || event.Cols <= 0 || event.Rows > 65535 || event.Cols > 65535 {
					inputErr <- errors.New("invalid terminal resize dimensions")
					return
				}
				if err := terminal.Resize(uint16(event.Rows), uint16(event.Cols)); err != nil {
					inputErr <- err
					return
				}
			case targetaccess.StreamEnd:
				inputErr <- io.EOF
				return
			default:
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

	buffer := make([]byte, 32*1024)
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
				_ = send(streamEvent(open, sequence, targetaccess.StreamError, nil, err.Error()))
				return err
			}
			_ = terminal.Close()
		default:
		}

		select {
		case result := <-waitResult:
			event := streamEvent(open, sequence, targetaccess.StreamExit, nil, "")
			event.ExitCode = &result.exitCode
			if result.err != nil {
				event.Message = result.err.Error()
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
					if result.err != nil {
						event.Message = result.err.Error()
					}
					return send(event)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			_ = send(streamEvent(open, sequence, targetaccess.StreamError, nil, readErr.Error()))
			return readErr
		}

		select {
		case <-ctx.Done():
			_ = send(streamEvent(open, sequence, targetaccess.StreamEnd, nil, ctx.Err().Error()))
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
