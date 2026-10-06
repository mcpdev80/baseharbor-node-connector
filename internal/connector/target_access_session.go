package connector

import (
	"context"
	"errors"
	"io"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func (a *TargetAccess) ServeSession(ctx context.Context, session *targetaccess.Session) error {
	if a == nil || session == nil {
		return errors.New("target access service and authenticated session are required")
	}
	return serveControlFrames(ctx, session, a.Execute, nil)
}

func (a *TargetAccess) ServeAnySession(ctx context.Context, session *targetaccess.Session) error {
	if a == nil || session == nil {
		return errors.New("target access service and authenticated session are required")
	}
	return serveControlFrames(ctx, session, a.Execute, func(ctx context.Context, open targetaccess.StreamOpen) error {
		switch open.Kind {
		case targetaccess.StreamLogs:
			return a.ServeLogStream(ctx, session, open)
		case targetaccess.StreamTerminal:
			return a.ServeTerminalStream(ctx, session, open)
		default:
			return errors.New("unsupported target access stream kind")
		}
	})
}

type controlWire interface {
	ReadInboundFrame() (targetaccess.InboundFrame, error)
	WriteResponse(targetaccess.Response) error
	Context() context.Context
	Close() error
}

type inboundControl struct {
	frame targetaccess.InboundFrame
	continueReading chan bool
}

type activeControl struct {
	ctx context.Context
	request targetaccess.Request
	cancel context.CancelFunc
}

func readControlFrames(ctx context.Context, wire controlWire, incoming chan<- inboundControl, failures chan<- error) {
	for {
		frame, err := wire.ReadInboundFrame()
		if err != nil {
			select {
			case failures <- err:
			case <-ctx.Done():
			}
			return
		}
		event := inboundControl{frame: frame, continueReading: make(chan bool, 1)}
		select {
		case incoming <- event:
		case <-ctx.Done():
			return
		}
		select {
		case proceed := <-event.continueReading:
			if !proceed {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// One request executes at a time per connection. The bounded frame reader stays
// available for its exact cancellation and disconnect; a stream takes exclusive
// read ownership and ends this connection rather than sharing terminal readers.
func serveControlFrames(
	ctx context.Context,
	wire controlWire,
	execute func(context.Context, targetaccess.Request) targetaccess.Response,
	stream func(context.Context, targetaccess.StreamOpen) error,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer wire.Close()
	stop := context.AfterFunc(wire.Context(), cancel)
	defer stop()
	stopClose := context.AfterFunc(ctx, func() { _ = wire.Close() })
	defer stopClose()
	incoming := make(chan inboundControl)
	failures := make(chan error, 1)
	completed := make(chan targetaccess.Response, 1)
	go readControlFrames(ctx, wire, incoming, failures)
	var active *activeControl
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-failures:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case response := <-completed:
			if active == nil {
				return errors.New("unexpected control completion")
			}
			if active.ctx.Err() != nil {
				response = targetaccess.FailureResponse(active.request, "cancelled", "The admitted operation was interrupted; reconcile its observed state.", false)
			}
			if err := wire.WriteResponse(response); err != nil {
				return err
			}
			active.cancel()
			active = nil
		case event := <-incoming:
			frame := event.frame
			switch {
			case frame.Cancel != nil:
				cancellation := frame.Cancel
				if active == nil || cancellation.RequestID != active.request.RequestID || cancellation.CorrelationID != active.request.CorrelationID {
					return errors.New("cancellation does not identify the active control request")
				}
				active.cancel()
				event.continueReading <- true
			case frame.Request != nil:
				request := *frame.Request
				if active != nil {
					if err := wire.WriteResponse(targetaccess.FailureResponse(request, "capability_unavailable", "The session already has an active operation.", false)); err != nil {
						return err
					}
					event.continueReading <- true
					continue
				}
				operationCtx, operationCancel := context.WithCancel(ctx)
				active = &activeControl{ctx: operationCtx, request: request, cancel: operationCancel}
				go func() {
					response := execute(operationCtx, request)
					if operationCtx.Err() != nil {
						response = targetaccess.FailureResponse(request, "cancelled", "The admitted operation was interrupted; reconcile its observed state.", false)
					}
					select {
					case completed <- response:
					case <-ctx.Done():
					}
				}()
				event.continueReading <- true
			case frame.StreamOpen != nil:
				if active != nil || stream == nil {
					return errors.New("stream requires an idle compatible session")
				}
				event.continueReading <- false
				return stream(ctx, *frame.StreamOpen)
			default:
				return errors.New("unsupported target access inbound frame")
			}
		}
	}
}
