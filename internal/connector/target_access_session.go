package connector

import (
	"context"
	"errors"
	"io"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func (a *TargetAccess) ServeSession(ctx context.Context, session *targetaccess.Session) error {
	if a == nil {
		return errors.New("target access service is required")
	}
	if session == nil {
		return errors.New("target access session is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(session.Context(), cancel)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var request targetaccess.Request
		if err := session.ReadRequest(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		response := a.Execute(ctx, request)
		if err := session.WriteResponse(response); err != nil {
			return err
		}
	}
}

func (a *TargetAccess) ServeAnySession(ctx context.Context, session *targetaccess.Session) error {
	if a == nil {
		return errors.New("target access service is required")
	}
	if session == nil {
		return errors.New("target access session is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(session.Context(), cancel)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		frame, err := session.ReadInboundFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch {
		case frame.Request != nil:
			response := a.Execute(ctx, *frame.Request)
			if err := session.WriteResponse(response); err != nil {
				return err
			}
		case frame.StreamOpen != nil:
			open := *frame.StreamOpen
			switch open.Kind {
			case targetaccess.StreamLogs:
				if err := a.ServeLogStream(ctx, session, open); err != nil {
					return err
				}
			case targetaccess.StreamTerminal:
				if err := a.ServeTerminalStream(ctx, session, open); err != nil {
					return err
				}
			default:
				return errors.New("unsupported target access stream kind")
			}
		default:
			return errors.New("unsupported target access inbound frame")
		}
	}
}
