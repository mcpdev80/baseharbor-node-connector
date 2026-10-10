package execx

import (
	"bytes"
	"context"
	"errors"
)

const maxCaptureBytes = 256 << 10

var ErrCaptureLimit = errors.New("bounded runtime result exceeds the capture limit")

type captureBuffer struct {
	buffer   bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

func (b *captureBuffer) Write(data []byte) (int, error) {
	if len(data) > maxCaptureBytes-b.buffer.Len() {
		size := maxCaptureBytes - b.buffer.Len()
		_, _ = b.buffer.Write(data[:size])
		b.exceeded = true
		b.cancel()
		return size, ErrCaptureLimit
	}
	return b.buffer.Write(data)
}

func (b *captureBuffer) String() string { return b.buffer.String() }
