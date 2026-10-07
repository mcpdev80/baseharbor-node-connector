//go:build !windows

package container

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/creack/pty"
)

type TerminalRequest struct {
	Argv        []string
	Workdir     string
	User        string
	Environment map[string]string
	Rows        uint16
	Cols        uint16
}

type TerminalSession struct {
	file   *os.File
	cmd    *exec.Cmd
	waitCh chan terminalResult
}

type terminalResult struct {
	exitCode int
	err      error
}

func (a *Adapter) StartTerminal(ctx context.Context, id string, request TerminalRequest) (*TerminalSession, error) {
	if err := validateResourceID(id); err != nil {
		return nil, err
	}
	if len(request.Argv) == 0 {
		return nil, fmt.Errorf("argv is required")
	}
	for _, arg := range request.Argv {
		if containsTerminalControl(arg) {
			return nil, fmt.Errorf("argv contains control character")
		}
	}
	if request.Rows == 0 {
		request.Rows = 24
	}
	if request.Cols == 0 {
		request.Cols = 80
	}

	command, err := a.runtime.Command()
	if err != nil {
		return nil, err
	}
	args := []string{"exec", "-i", "-t"}
	if user := strings.TrimSpace(request.User); user != "" {
		if containsTerminalControl(user) {
			return nil, fmt.Errorf("invalid terminal user")
		}
		args = append(args, "--user", user)
	}
	if workdir := strings.TrimSpace(request.Workdir); workdir != "" {
		if containsTerminalControl(workdir) {
			return nil, fmt.Errorf("invalid terminal workdir")
		}
		args = append(args, "--workdir", workdir)
	}
	for key, value := range request.Environment {
		if strings.TrimSpace(key) == "" || strings.Contains(key, "=") || containsTerminalControl(key) {
			return nil, fmt.Errorf("invalid environment key")
		}
		if containsTerminalControl(value) {
			return nil, fmt.Errorf("invalid environment value")
		}
		args = append(args, "--env", key+"="+value)
	}
	args = append(args, id)
	args = append(args, request.Argv...)

	cmd := exec.CommandContext(ctx, command, args...)
	ptmx, err := startTransportPTY(cmd, request.Rows, request.Cols)
	if err != nil {
		return nil, err
	}

	session := &TerminalSession{
		file:   ptmx,
		cmd:    cmd,
		waitCh: make(chan terminalResult, 1),
	}
	go func() {
		err := cmd.Wait()
		exitCode := 0
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		session.waitCh <- terminalResult{exitCode: exitCode, err: err}
		close(session.waitCh)
	}()
	return session, nil
}

func (s *TerminalSession) Read(p []byte) (int, error) {
	n, err := s.file.Read(p)
	if errors.Is(err, syscall.EIO) {
		return n, io.EOF
	}
	return n, err
}

func (s *TerminalSession) Write(p []byte) (int, error) {
	return s.file.Write(p)
}

func (s *TerminalSession) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return fmt.Errorf("terminal rows and cols must be positive")
	}
	return pty.Setsize(s.file, &pty.Winsize{Rows: rows, Cols: cols})
}

func (s *TerminalSession) Wait() (int, error) {
	result, ok := <-s.waitCh
	if !ok {
		if s.cmd.ProcessState != nil {
			return s.cmd.ProcessState.ExitCode(), nil
		}
		return 0, nil
	}
	return result.exitCode, result.err
}

func (s *TerminalSession) Close() error {
	if s == nil || s.file == nil {
		return nil
	}
	return s.file.Close()
}

func containsTerminalControl(value string) bool {
	for _, r := range value {
		if r == rune(0) || r == rune(10) || r == rune(13) {
			return true
		}
	}
	return false
}

var _ io.ReadWriteCloser = (*TerminalSession)(nil)
