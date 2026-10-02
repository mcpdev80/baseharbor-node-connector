package capability

import "testing"

func TestDockerDisablesQuadletCapabilities(t *testing.T) {
	caps := ForRuntime("docker")
	for _, cap := range caps {
		if cap.Name == QuadletApply || cap.Name == QuadletRemove {
			if cap.Available {
				t.Fatalf("%s must be disabled for Docker", cap.Name)
			}
		}
	}
}

func TestPodmanKeepsQuadletCapabilities(t *testing.T) {
	caps := ForRuntime("podman")
	for _, name := range []Name{QuadletApply, QuadletRemove} {
		found := false
		for _, cap := range caps {
			if cap.Name == name {
				found = true
				if !cap.Available {
					t.Fatalf("%s must be available for Podman", name)
				}
			}
		}
		if !found {
			t.Fatalf("missing capability %s", name)
		}
	}
}
