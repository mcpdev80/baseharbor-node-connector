package quadlet

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

const bundlePathPrefix = "@BASEHARBOR_BUNDLE@/"

// ApplyPublished consumes exact committed source, then resolves only explicit
// bundle file references on this node. The Core never supplies a node host path.
func (m *Manager) ApplyPublished(ctx context.Context, root *fssecure.Root, directory, name, content string, enable bool) error {
	if _, _, err := m.resolve(name); err != nil {
		return err
	}
	resolved, err := resolvePublishedContent(root, directory, name, content)
	if err != nil {
		return err
	}
	if err := m.checkPublishedNativeOwnership(ctx, name, resolved); err != nil {
		return err
	}
	return m.Apply(ctx, name, resolved, enable)
}

func resolvePublishedContent(root *fssecure.Root, directory, name, content string) (string, error) {
	if root == nil || filepath.Base(name) != name {
		return "", errors.New("published Quadlet selection is invalid")
	}
	member := filepath.Join(directory, name)
	if err := root.VerifyPublishedBundle(directory, member); err != nil {
		return "", err
	}
	file, err := root.Existing(member)
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(file)
	if err != nil || len(data) > 262144 || !bytes.Equal(data, []byte(content)) {
		return "", errors.New("published Quadlet content differs")
	}
	lines := strings.Split(content, "\n")
	section := ""
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = trimmed
		}
		if !strings.Contains(line, "@BASEHARBOR_BUNDLE@") {
			if section == "[Container]" {
				key, value, _ := strings.Cut(line, "=")
				if key == "EnvironmentFile" || (key == "Volume" && strings.ContainsAny(strings.Split(value, ":")[0], "/\\")) {
					return "", errors.New("published Quadlet host files require explicit bundle bindings")
				}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section != "[Container]" || (key != "Volume" && key != "EnvironmentFile") ||
			!strings.HasPrefix(value, bundlePathPrefix) || strings.HasSuffix(line, "\\") {
			return "", errors.New("unsupported Quadlet bundle reference")
		}
		relative := strings.TrimPrefix(value, bundlePathPrefix)
		suffix := ""
		if key == "Volume" {
			parts := strings.Split(relative, ":")
			if len(parts) != 3 || !strings.HasPrefix(parts[1], "/") || parts[2] != "ro" {
				return "", errors.New("bundle mounts must be explicit read-only file bindings")
			}
			relative, suffix = parts[0], ":"+parts[1]+":ro"
		}
		if relative == "." || relative == "" || filepath.Clean(relative) != relative || filepath.IsAbs(relative) ||
			relative == ".." || strings.HasPrefix(relative, "../") || strings.ContainsAny(relative, "\\\x00\r\n:%\"") {
			return "", errors.New("Quadlet bundle file must be confined")
		}
		binding := filepath.Join(directory, relative)
		if err := root.VerifyPublishedBundle(directory, binding); err != nil {
			return "", err
		}
		absolute, err := root.Existing(binding)
		if err != nil || strings.ContainsAny(absolute, ":\x00\r\n") {
			return "", errors.New("Quadlet bundle file is unavailable")
		}
		if key == "EnvironmentFile" {
			info, err := os.Stat(absolute)
			if err != nil || info.Mode().Perm() != 0600 {
				return "", errors.New("Quadlet environment must remain owner-only")
			}
		}
		value = strings.ReplaceAll(absolute, "%", "%%") + suffix
		// Volume uses Quadlet's raw value parser; surrounding quotes would
		// become part of the host filename. EnvironmentFile parses argv words.
		if key == "EnvironmentFile" {
			value = strconv.Quote(value)
		}
		lines[i] = key + "=" + value
	}
	// Podman storage/registry process defaults are selected by this Node's
	// installation; never inherit the Core host's filesystem configuration.
	for _, key := range []string{"CONTAINERS_STORAGE_CONF", "CONTAINERS_REGISTRIES_CONF", "STORAGE_DRIVER", "STORAGE_OPTS"} {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return "", errors.New("invalid native runtime environment")
		}
		lines = append(lines, "[Service]", "Environment="+strconv.Quote(strings.ReplaceAll(key+"="+value, "%", "%%")))
	}
	return strings.Join(lines, "\n"), nil
}
