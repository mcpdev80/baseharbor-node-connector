package health

import (
	"strings"
	"testing"
)

func TestNodeMemoryRequiresAvailableEvidenceAndConsistentUnits(t *testing.T) {
	valid := "MemTotal: 1024 kB\nMemAvailable: 512 kB\nSwapTotal: 256 kB\nSwapFree: 128 kB\n"
	memory, err := parseNodeMemory(strings.NewReader(valid))
	if err != nil || memory.AvailableBytes != 512*1024 || memory.TotalBytes != 1024*1024 {
		t.Fatal(memory, err)
	}
	for _, input := range []string{
		strings.ReplaceAll(valid, "MemAvailable: 512 kB\n", ""),
		strings.ReplaceAll(valid, "512 kB", "2048 kB"),
		strings.ReplaceAll(valid, "128 kB", "512 kB"),
		strings.ReplaceAll(valid, "1024 kB", "18446744073709551615 kB"),
		strings.ReplaceAll(valid, "512 kB", "512 MB"),
		valid + "MemTotal: 1024 kB\n",
	} {
		if _, err := parseNodeMemory(strings.NewReader(input)); err == nil {
			t.Fatal("incomplete or invalid node capacity admitted", input)
		}
	}
	if memory, err := parseNodeMemory(strings.NewReader(strings.ReplaceAll(valid, "512 kB", "0 kB"))); err != nil || memory.AvailableBytes != 0 {
		t.Fatal("exhausted capacity must remain valid evidence", memory, err)
	}
}
