//go:build !windows

package container

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPTYTransportsEarlyInputBytesWithoutLineDiscipline(t *testing.T) {
	payload := []byte("echo terminal-ok\r\x03\x7f\x1b[A")
	if os.Getenv("BASEHARBOR_TEST_PTY_BYTE_TRANSPORT") == "1" {
		data := make([]byte, len(payload))
		if _, err := io.ReadFull(os.Stdin, data); err != nil {
			os.Exit(2)
		}
		fmt.Printf("received:%s", hex.EncodeToString(data))
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPTYTransportsEarlyInputBytesWithoutLineDiscipline$")
	cmd.Env = append(os.Environ(), "BASEHARBOR_TEST_PTY_BYTE_TRANSPORT=1")
	session, err := startTransportPTY(cmd, 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	defer cmd.Wait()
	if n, err := session.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("input write = %d, %v", n, err)
	}
	data, _ := io.ReadAll(session)
	if !strings.Contains(string(data), "received:"+hex.EncodeToString(payload)) {
		t.Fatalf("PTY changed or withheld early input bytes: %q", data)
	}
}
