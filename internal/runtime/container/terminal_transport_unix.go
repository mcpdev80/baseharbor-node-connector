//go:build !windows

package container

import (
	"github.com/charmbracelet/x/term"
	"github.com/creack/pty"
	"os"
	"os/exec"
	"syscall"
)

// The outer PTY transports bytes to the runtime CLI. The container's inner
// terminal owns echo, signals and line editing. Configure the transport before
// starting the CLI so early input cannot be buffered, translated or erased by
// the outer terminal while the CLI initializes its own raw mode.
func startTransportPTY(cmd *exec.Cmd, rows, columns uint16) (*os.File, error) {
	master, slave, err := pty.Open()
	if err != nil {
		return nil, err
	}
	defer slave.Close()
	if _, err = term.MakeRaw(slave.Fd()); err == nil {
		err = pty.Setsize(master, &pty.Winsize{Rows: rows, Cols: columns})
	}
	if err != nil {
		_ = master.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid, cmd.SysProcAttr.Setctty = true, true
	if err := cmd.Start(); err != nil {
		_ = master.Close()
		return nil, err
	}
	return master, nil
}
