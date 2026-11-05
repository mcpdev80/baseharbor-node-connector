package execx

import (
	"context"
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
	// Run the executable in its own process group and set a wait delay so that
	// when ctx is cancelled the whole group is killed, not just the direct
	// child. A child that outlives its parent (e.g. a `docker logs --follow`
	// wrapper shell holding the stdout pipe open via a backgrounded `sleep`)
	// would otherwise keep the reader blocked forever after the ctx deadline
	// fires, so the stream never ends and no terminal event is delivered.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 500 * time.Millisecond
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
		// perspective that is a clean end of the log stream, so close the pipe
		// with io.EOF rather than the kill error: ServeLogStream then emits the
		// terminal StreamEnd instead of a StreamError.
		_ = cmd.Wait()
		_ = writer.CloseWithError(io.EOF)
	}()
	return reader, nil
}
