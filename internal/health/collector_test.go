package health

import "testing"

func TestInfoConversionHelpers(t *testing.T) {
	values := map[string]any{
		"ServerVersion": "27.1.0",
		"MemTotal":      float64(1024),
		"Containers":    "4",
	}
	if got := firstString(values, "ServerVersion"); got != "27.1.0" {
		t.Fatalf("unexpected version %q", got)
	}
	if got := firstInt64(values, "MemTotal"); got != 1024 {
		t.Fatalf("unexpected memory %d", got)
	}
	if got := firstInt64(values, "Containers"); got != 4 {
		t.Fatalf("unexpected containers %d", got)
	}
}
