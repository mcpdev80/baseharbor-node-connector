package runtime

import (
	"context"
	"errors"
	"strings"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
)

type Kind string

const (
	Docker  Kind = "docker"
	Podman  Kind = "podman"
	Unknown Kind = "unknown"
)

type Detection struct {
	Kind    Kind   `json:"kind"`
	Version string `json:"version,omitempty"`
}

type Detector struct {
	runner execx.Runner
}

func NewDetector() *Detector {
	return &Detector{runner: execx.Runner{}}
}

func (d *Detector) Detect(ctx context.Context) (Detection, error) {
	if result, err := d.runner.Run(ctx, nil, "docker", "info", "--format", "{{.ServerVersion}}"); err == nil {
		return Detection{Kind: Docker, Version: strings.TrimSpace(result.Stdout)}, nil
	}
	if result, err := d.runner.Run(ctx, nil, "podman", "info", "--format", "{{.Version.Version}}"); err == nil {
		return Detection{Kind: Podman, Version: strings.TrimSpace(result.Stdout)}, nil
	}
	return Detection{Kind: Unknown}, errors.New("no reachable Docker or Podman runtime found")
}

// DetectKind verifies only the runtime selected by the enrolled Target. It
// must not substitute another reachable engine when that runtime is absent.
func (d *Detector) DetectKind(ctx context.Context, kind Kind) (Detection, error) {
	command, err := kind.Command()
	if err != nil {
		return Detection{Kind: Unknown}, err
	}
	format := "{{.ServerVersion}}"
	if kind == Podman {
		format = "{{.Version.Version}}"
	}
	result, err := d.runner.Run(ctx, nil, command, "info", "--format", format)
	if err != nil {
		return Detection{Kind: Unknown}, errors.New("selected enrolled runtime is unavailable")
	}
	return Detection{Kind: kind, Version: strings.TrimSpace(result.Stdout)}, nil
}

func (k Kind) Command() (string, error) {
	switch k {
	case Docker:
		return "docker", nil
	case Podman:
		return "podman", nil
	default:
		return "", errors.New("unknown runtime")
	}
}
