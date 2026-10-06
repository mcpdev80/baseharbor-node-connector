package capability

import goruntime "runtime"

func ForRuntime(runtime string) []Descriptor {
	result := Baseline()
	if goruntime.GOOS == "windows" {
		for i := range result {
			if result[i].Name == Terminal {
				result[i].Available = false
				result[i].Detail = "PTY terminal sessions are unsupported on Windows"
			}
		}
	}
	if runtime != "podman" || goruntime.GOOS != "linux" {
		for i := range result {
			switch result[i].Name {
			case QuadletApply, QuadletRemove, QuadletEnable, QuadletDisable:
				result[i].Available = false
				result[i].Detail = "Linux Podman with a live systemd user manager is required"
			}
		}
	}
	return result
}
