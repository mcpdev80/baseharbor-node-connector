package execx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestCaptureHelperProcess(t *testing.T) {
	stream := os.Getenv("BASEHARBOR_TEST_CAPTURE_STREAM")
	if stream == "" {
		return
	}
	destination := os.Stdout
	if stream == "stderr" {
		destination = os.Stderr
	}
	data := bytes.Repeat([]byte("x"), maxCaptureBytes*4)
	_, _ = destination.Write(data)
	os.Exit(0)
}

func TestRuntimeCaptureOverflowCancelsProcessAndReturnsNoPartialResult(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			started := time.Now()
			result, err := (Runner{}).Run(ctx, map[string]string{"BASEHARBOR_TEST_CAPTURE_STREAM": stream}, os.Args[0], "-test.run=^TestCaptureHelperProcess$")
			if !errors.Is(err, ErrCaptureLimit) || result.Stdout != "" || result.Stderr != "" {
				t.Fatal("overflow returned unbounded/partial result", err)
			}
			if time.Since(started) > 3*time.Second {
				t.Fatal("overflow did not retire producer promptly")
			}
		})
	}
}
