package capability

func ForRuntime(runtime string) []Descriptor {
	result := Baseline()
	if runtime != "podman" {
		for i := range result {
			switch result[i].Name {
			case QuadletApply, QuadletRemove:
				result[i].Available = false
				result[i].Detail = "Podman targets only"
			}
		}
	}
	return result
}
