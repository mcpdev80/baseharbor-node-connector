//go:build windows

package container

import (
	"context"
	"errors"
)

type TerminalRequest struct {
	Argv        []string
	Workdir     string
	User        string
	Environment map[string]string
	Rows        uint16
	Cols        uint16
}

type TerminalSession struct{}

func (a *Adapter) StartTerminal(context.Context, string, TerminalRequest) (*TerminalSession, error) {
	return nil, errors.New("PTY terminal sessions are unsupported on Windows")
}

func (s *TerminalSession) Read([]byte) (int, error) { return 0, errors.New("PTY terminal sessions are unsupported on Windows") }
func (s *TerminalSession) Write([]byte) (int, error) { return 0, errors.New("PTY terminal sessions are unsupported on Windows") }
func (s *TerminalSession) Resize(uint16, uint16) error { return errors.New("PTY terminal sessions are unsupported on Windows") }
func (s *TerminalSession) Wait() (int, error) { return 0, errors.New("PTY terminal sessions are unsupported on Windows") }
func (s *TerminalSession) Close() error { return nil }
