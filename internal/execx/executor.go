package execx

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
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
		err := cmd.Wait()
		_ = writer.CloseWithError(err)
	}()
	return reader, nil
}
