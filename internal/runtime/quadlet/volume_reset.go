package quadlet

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

// ResetPublishedVolume consumes an explicit Core reset decision after owned
// unit teardown. It requires exact retained realization and live native labels,
// never force-removes an in-use volume and never stops another workload.
func (m *Manager) ResetPublishedVolume(ctx context.Context, root *fssecure.Root, directory, name, content string) error {
	if filepath.Ext(name) != ".volume" {
		return errors.New("published volume reset requires a volume unit")
	}
	if _, _, err := m.resolve(name); err != nil {
		return err
	}
	resolved, err := resolvePublishedContent(root, directory, name, content)
	if err != nil {
		return err
	}
	release, err := m.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	if err := m.verifyRetainedResource(name, []byte(resolved)); err != nil {
		return errors.New("volume reset requires exact owned teardown")
	}
	if err := m.checkPublishedNativeOwnership(ctx, name, resolved); err != nil {
		return err
	}
	section, volume := "", ""
	for _, line := range strings.Split(resolved, "\n") {
		if strings.HasPrefix(line, "[") {
			section = line
		}
		if section == "[Volume]" && strings.HasPrefix(line, "VolumeName=") {
			if volume != "" {
				return errors.New("ambiguous published volume")
			}
			volume = strings.TrimPrefix(line, "VolumeName=")
		}
	}
	if !nativeResourceName.MatchString(volume) {
		return errors.New("invalid published volume identity")
	}
	exists, err := m.runner.Run(ctx, nil, "podman", "volume", "exists", volume)
	if err != nil && exists.ExitCode == 1 {
		return nil
	}
	if err != nil {
		return errors.New("published volume observation failed")
	}
	// Native rm without force independently refuses any live consumer.
	if _, err := m.runner.Run(ctx, nil, "podman", "volume", "rm", volume); err != nil {
		return errors.New("owned volume reset failed")
	}
	// Do not infer success from the removal command alone.
	result, err := m.runner.Run(ctx, nil, "podman", "volume", "exists", volume)
	if err == nil || result.ExitCode != 1 {
		return errors.New("owned volume reset is unverified")
	}
	return nil
}
