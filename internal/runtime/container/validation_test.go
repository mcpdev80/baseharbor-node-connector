package container

import "testing"

func TestValidateResourceID(t *testing.T) {
	valid := []string{"abc123", "name-with.dots_1"}
	for _, value := range valid {
		if err := validateResourceID(value); err != nil {
			t.Fatalf("expected %q to be valid: %v", value, err)
		}
	}

	invalid := []string{"", "   ", "abc\n123", "abc\x00123"}
	for _, value := range invalid {
		if err := validateResourceID(value); err == nil {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}

func TestValidateResourceNameRejectsPaths(t *testing.T) {
	for _, value := range []string{"", "../x", "a/b", "a\\b", "x\n"} {
		if err := validateResourceName(value); err == nil {
			t.Fatalf("expected %q to be invalid", value)
		}
	}
}
