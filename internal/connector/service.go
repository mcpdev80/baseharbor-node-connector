package connector

import (
	"context"
	"fmt"

	"github.com/mcpdev80/baseharbor-node-connector/internal/capability"
	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/compose"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/container"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/quadlet"
)

type Config struct {
	Runtime            runtime.Kind
	StagingRoot        string
	TransportStateRoot string
	QuadletRoot        string
}

type Service struct {
	Runtime            runtime.Detection
	Capabilities       []capability.Descriptor
	Observation        *container.Adapter
	Inventory          *container.Resources
	Realizer           *container.Lifecycle
	Compose            *compose.Adapter
	Quadlet            *quadlet.Manager
	Staging            *fssecure.Root
	TransportStateRoot string
}

func Open(ctx context.Context, cfg Config) (*Service, error) {
	detector := runtime.NewDetector()
	var detection runtime.Detection
	var err error
	if cfg.Runtime == "" {
		detection, err = detector.Detect(ctx)
	} else {
		detection, err = detector.DetectKind(ctx, cfg.Runtime)
	}
	if err != nil {
		return nil, fmt.Errorf("detect runtime: %w", err)
	}

	staging, err := fssecure.OpenRoot(cfg.StagingRoot)
	if err != nil {
		return nil, fmt.Errorf("open staging root: %w", err)
	}

	quadletManager, err := quadlet.NewManager(cfg.QuadletRoot)
	if err != nil {
		return nil, fmt.Errorf("open quadlet manager: %w", err)
	}

	capabilities := capability.ForRuntime(string(detection.Kind))
	if detection.Kind == runtime.Podman && !quadletManager.Available(ctx) {
		for i := range capabilities {
			switch capabilities[i].Name {
			case capability.QuadletApply, capability.QuadletRemove, capability.QuadletEnable, capability.QuadletDisable:
				capabilities[i].Available = false
				capabilities[i].Detail = "A reachable systemd user manager is required"
			}
		}
	}

	return &Service{
		Runtime:            detection,
		Capabilities:       capabilities,
		Observation:        container.NewAdapter(detection.Kind),
		Inventory:          container.NewResources(detection.Kind),
		Realizer:           container.NewLifecycle(detection.Kind),
		Compose:            compose.NewAdapter(detection.Kind, staging),
		Quadlet:            quadletManager,
		Staging:            staging,
		TransportStateRoot: cfg.TransportStateRoot,
	}, nil
}
