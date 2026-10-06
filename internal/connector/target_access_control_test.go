package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

type testControlWire struct {
	ctx context.Context
	cancel context.CancelFunc
	frames chan targetaccess.InboundFrame
	responses chan targetaccess.Response
	closeOnce sync.Once
	reads atomic.Int32
}

func newTestControlWire(t *testing.T) *testControlWire {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	wire := &testControlWire{ctx: ctx, cancel: cancel, frames: make(chan targetaccess.InboundFrame, 4), responses: make(chan targetaccess.Response, 4)}
	t.Cleanup(func() { _ = wire.Close() })
	return wire
}

func (w *testControlWire) ReadInboundFrame() (targetaccess.InboundFrame, error) {
	w.reads.Add(1)
	select {
	case frame := <-w.frames:
		return frame, nil
	case <-w.ctx.Done():
		return targetaccess.InboundFrame{}, io.EOF
	}
}
func (w *testControlWire) WriteResponse(response targetaccess.Response) error {
	data, err := json.Marshal(response)
	if err != nil || targetaccess.ValidateTargetAccessRecord("response", data) != nil {
		return targetaccess.ErrTargetAccessWire
	}
	select {
	case w.responses <- response:
		return nil
	case <-w.ctx.Done():
		return w.ctx.Err()
	}
}
func (w *testControlWire) Context() context.Context { return w.ctx }
func (w *testControlWire) Close() error { w.closeOnce.Do(w.cancel); return nil }

func controlRequest(id string) targetaccess.Request {
	return targetaccess.Request{ContractVersion: targetaccess.ContractVersion, ProtocolVersion: targetaccess.ProtocolVersion,
		RequestID: id, CorrelationID: "corr-a", TargetID: "target-a", Operation: targetaccess.OpCapabilities,
		Payload: json.RawMessage("{}"), IssuedAt: time.Now().UTC(), DeadlineAt: time.Now().UTC().Add(time.Minute)}
}

func controlCancellation(request targetaccess.Request) *targetaccess.Cancel {
	return &targetaccess.Cancel{ContractVersion: request.ContractVersion, ProtocolVersion: request.ProtocolVersion,
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, Cancel: true}
}

func waitControlSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal("bounded control signal did not arrive")
	}
}

func TestControlCancellationInterruptsOnlyTheExactActiveRequest(t *testing.T) {
	for _, variant := range []string{"exact", "foreign-request", "foreign-correlation", "disconnect"} {
		t.Run(variant, func(t *testing.T) {
			wire := newTestControlWire(t)
			started, interrupted := make(chan struct{}), make(chan struct{})
			finished := make(chan error, 1)
			go func() {
				finished <- serveControlFrames(context.Background(), wire, func(ctx context.Context, request targetaccess.Request) targetaccess.Response {
					close(started)
					<-ctx.Done()
					close(interrupted)
					return targetaccess.SuccessResponse(request, json.RawMessage("{}"))
				}, nil)
			}()
			request := controlRequest("active-a")
			wire.frames <- targetaccess.InboundFrame{Request: &request}
			waitControlSignal(t, started)
			if variant == "disconnect" {
				_ = wire.Close()
			} else {
				cancellation := controlCancellation(request)
				if variant == "foreign-request" {
					cancellation.RequestID = "foreign"
				}
				if variant == "foreign-correlation" {
					cancellation.CorrelationID = "foreign"
				}
				wire.frames <- targetaccess.InboundFrame{Cancel: cancellation}
			}
			waitControlSignal(t, interrupted)
			if variant == "exact" {
				select {
				case response := <-wire.responses:
					if response.Success || response.Error == nil || response.Error.Code != "cancelled" || response.RequestID != request.RequestID || response.CorrelationID != request.CorrelationID {
						t.Fatal("cancelled operation was reported successful or lost its correlation", response)
					}
				case <-time.After(time.Second):
					t.Fatal("cancellation did not return a bounded typed outcome")
				}
				_ = wire.Close()
			}
			select {
			case err := <-finished:
				if variant != "exact" && variant != "disconnect" && err == nil {
					t.Fatal("foreign cancellation did not fail the session closed")
				}
			case <-time.After(time.Second):
				t.Fatal("control session did not close")
			}
		})
	}
}

func TestControlConnectionRejectsConcurrentAdmission(t *testing.T) {
	wire := newTestControlWire(t)
	started, interrupted := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	go func() {
		_ = serveControlFrames(context.Background(), wire, func(ctx context.Context, request targetaccess.Request) targetaccess.Response {
			calls.Add(1)
			close(started)
			<-ctx.Done()
			close(interrupted)
			return targetaccess.SuccessResponse(request, json.RawMessage("{}"))
		}, nil)
	}()
	first, second := controlRequest("first"), controlRequest("second")
	wire.frames <- targetaccess.InboundFrame{Request: &first}
	waitControlSignal(t, started)
	wire.frames <- targetaccess.InboundFrame{Request: &second}
	select {
	case response := <-wire.responses:
		if response.Success || response.Error == nil || response.Error.Code != "capability_unavailable" || response.RequestID != second.RequestID || calls.Load() != 1 {
			t.Fatal("busy connection admitted a second runtime invocation", response, calls.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent admission did not fail within the bound")
	}
	_ = wire.Close()
	waitControlSignal(t, interrupted)
}

func TestStreamHandoffStopsTheControlReaderBeforeStreamOwnership(t *testing.T) {
	wire := newTestControlWire(t)
	finished := make(chan error, 1)
	streamError := errors.New("test stream finished")
	go func() {
		finished <- serveControlFrames(context.Background(), wire, func(context.Context, targetaccess.Request) targetaccess.Response {
			return targetaccess.Response{}
		}, func(context.Context, targetaccess.StreamOpen) error {
			if wire.reads.Load() != 1 {
				return errors.New("control reader continued into the stream")
			}
			return streamError
		})
	}()
	open := targetaccess.StreamOpen{StreamID: "stream-a"}
	wire.frames <- targetaccess.InboundFrame{StreamOpen: &open}
	select {
	case err := <-finished:
		if !errors.Is(err, streamError) || wire.reads.Load() != 1 {
			t.Fatal("stream read ownership was not exclusive", err, wire.reads.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("stream handoff did not complete")
	}
}
