package quadlet

import (
	"context"
	"errors"
	"strings"
)

// Quadlet stop normally retains networks. Remove only the exact owned network
// after stopping its unit, without forcing removal of any live consumer.
func (m *Manager) removeOwnedNetwork(ctx context.Context, unit, content string) error {
	if err := m.checkPublishedNativeOwnership(ctx, unit, content); err != nil {
		return err
	}
	section, name := "", ""
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "[") {
			section = line
		}
		if section == "[Network]" && strings.HasPrefix(line, "NetworkName=") {
			if name != "" {
				return errors.New("ambiguous published network")
			}
			name = strings.TrimPrefix(line, "NetworkName=")
		}
	}
	if !nativeResourceName.MatchString(name) {
		return errors.New("invalid published network identity")
	}
	result, err := m.runner.Run(ctx, nil, "podman", "network", "exists", name)
	if err != nil && result.ExitCode == 1 {
		return nil
	}
	if err != nil {
		return errors.New("published network observation failed")
	}
	if _, err := m.runner.Run(ctx, nil, "podman", "network", "rm", name); err != nil {
		return errors.New("owned network removal failed")
	}
	result, err = m.runner.Run(ctx, nil, "podman", "network", "exists", name)
	if err == nil || result.ExitCode != 1 {
		return errors.New("owned network removal is unverified")
	}
	return nil
}
