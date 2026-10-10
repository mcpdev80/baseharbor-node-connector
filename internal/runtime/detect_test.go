package runtime

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSelectedRuntimeCannotFallBackToAnotherReachableEngine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix executable fixture")
	}
	for _, selected := range []Kind{Docker, Podman} {
		t.Run(string(selected), func(t *testing.T) {
			dir := t.TempDir()
			other := Docker
			if selected == Docker {
				other = Podman
			}
			marker := filepath.Join(dir, "wrong-engine-called")
			// This executable is a source-test spy, never runtime evidence.
			if err := os.WriteFile(filepath.Join(dir, string(other)), []byte("#!/bin/sh\nprintf reached > '"+marker+"'\nprintf version\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			if _, err := NewDetector().DetectKind(context.Background(), selected); err == nil {
				t.Fatal("unavailable selected runtime accepted")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("selection probed a different engine", err)
			}
		})
	}
}
