package quadlet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var nativeResourceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// A matching host name is not permission to adopt a native resource. Repair
// needs both the protected unit realization receipt and matching native labels.
func (m *Manager) checkPublishedNativeOwnership(ctx context.Context, unit, content string) error {
	ext := filepath.Ext(unit)
	kind, section, nameKey := "", "", ""
	switch ext {
	case ".container":
		kind, section, nameKey = "container", "[Container]", "ContainerName"
	case ".network":
		kind, section, nameKey = "network", "[Network]", "NetworkName"
	case ".volume":
		kind, section, nameKey = "volume", "[Volume]", "VolumeName"
	default:
		return errors.New("published Quadlet kind is unsupported")
	}
	current, name, project, service := "", "", "", ""
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "[") {
			current = line
		}
		if current != section {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		if key == nameKey {
			if name != "" {
				return errors.New("ambiguous native resource name")
			}
			name = value
		}
		if key == "Label" {
			label, value, _ := strings.Cut(value, "=")
			switch label {
			case "com.docker.compose.project":
				if project != "" {
					return errors.New("ambiguous native ownership label")
				}
				project = value
			case "com.docker.compose.service":
				if service != "" {
					return errors.New("ambiguous native service label")
				}
				service = value
			}
		}
	}
	if !nativeResourceName.MatchString(name) || !nativeResourceName.MatchString(project) ||
		(kind == "container" && !nativeResourceName.MatchString(service)) {
		return errors.New("published Quadlet lacks explicit native ownership")
	}
	exists, err := m.runner.Run(ctx, nil, "podman", kind, "exists", name)
	if err != nil && exists.ExitCode == 1 {
		return nil
	}
	if err != nil {
		return errors.New("native ownership inspection is unavailable")
	}
	if err := m.verifyOwned(unit); err != nil {
		if kind == "container" || !errors.Is(err, os.ErrNotExist) || m.verifyRetainedResource(unit, []byte(content)) != nil {
			return errors.New("existing native resource has no owned realization receipt")
		}
	}
	result, err := m.runner.Run(ctx, nil, "podman", kind, "inspect", name)
	if err != nil {
		return errors.New("native resource inspection failed")
	}
	var records []struct {
		Labels map[string]string `json:"Labels"`
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if json.Unmarshal([]byte(result.Stdout), &records) != nil || len(records) != 1 {
		return errors.New("native resource inspection is invalid")
	}
	labels := records[0].Labels
	if kind == "container" {
		labels = records[0].Config.Labels
	}
	if labels["com.docker.compose.project"] != project || (kind == "container" && labels["com.docker.compose.service"] != service) {
		return errors.New("foreign native resource must be preserved")
	}
	return nil
}
