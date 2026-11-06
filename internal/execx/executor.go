package execx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Result is a bounded process result. Callers decide what output is safe to expose.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes explicitly selected local binaries. It does not invoke a shell.
type Runner struct{}

func (Runner) Run(ctx context.Context, env map[string]string, name string, args ...string) (Result, error) {
	if strings.TrimSpace(name) == "" {
		return Result{}, fmt.Errorf("executable is required")
	}

	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(lifetime, name, args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = os.Environ()
	for key, value := range env {
		if strings.TrimSpace(key) == "" ||
			strings.Contains(key, "=") ||
			strings.ContainsRune(key, rune(0)) ||
			strings.ContainsRune(key, '\r') ||
			strings.ContainsRune(key, '\n') {
			return Result{}, fmt.Errorf("invalid environment key")
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	stdout := captureBuffer{cancel: cancel}
	stderr := captureBuffer{cancel: cancel}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := Result{
		Stdout: strings.TrimSpace(stdout.String()),
		Stderr: strings.TrimSpace(stderr.String()),
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if stdout.exceeded || stderr.exceeded {
		return Result{ExitCode: result.ExitCode}, ErrCaptureLimit
	}

	if err != nil {
		if result.Stderr != "" {
			return result, fmt.Errorf("%w: %s", err, result.Stderr)
		}
		return result, err
	}
	return result, nil
}

func (Runner) Stream(ctx context.Context, env map[string]string, name string, args ...string) (io.ReadCloser, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("executable is required")
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = os.Environ()
	for key, value := range env {
		if strings.TrimSpace(key) == "" ||
			strings.Contains(key, "=") ||
			strings.ContainsRune(key, rune(0)) ||
			strings.ContainsRune(key, rune(13)) ||
			strings.ContainsRune(key, rune(10)) {
			return nil, fmt.Errorf("invalid environment key")
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	reader, writer := io.Pipe()
	cmd.Stdout = writer
	cmd.Stderr = writer
	if err := cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		return nil, err
	}
	go func() {
		// The ctx deadline ends a follow stream by cancelling the context, which
		// kills the runtime subprocess (exec.CommandContext). From the reader's
		// perspective that is a clean end of the log stream, so a context kill is
		// mapped to io.EOF: ServeLogStream then emits the terminal StreamEnd
		// instead of a StreamError. A real child failure, however, must NOT be
		// hidden as a clean end: its wait error is forwarded so ServeLogStream
		// emits a StreamError instead.
		//
		// exec.CommandContext reaps a still-running child on context
		// cancellation/deadline with its SIGKILL (after WaitDelay), so cmd.Wait()
		// returns an *exec.ExitError whose ProcessState was killed by the signal
		// (syscall.WaitStatus.Signaled() == true) rather than exiting on its own
		// with a non-zero code. That killed-by-context shape is the only clean
		// EOF; a non-zero exit the child produced on its own is a genuine
		// failure and must surface.
		waitErr := cmd.Wait()
		if waitErr == nil || isContextKilled(waitErr) {
			_ = writer.CloseWithError(io.EOF)
			return
		}
		_ = writer.CloseWithError(waitErr)
	}()
	return reader, nil
}

// isContextKilled reports whether err is an *exec.ExitError whose process was
// reaped by exec.CommandContext's own signal (context cancellation or deadline),
// as opposed to a child that exited on its own with a non-zero status. A
// context-killed child is a clean stream end for the caller; a real non-zero
// exit is a genuine failure that must surface as a stream error.
func isContextKilled(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	ps := exitErr.ProcessState
	if ps == nil {
		return false
	}
	ws, ok := ps.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled()
}
