package deployment

import (
	"context"

	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/compose"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/container"
	"github.com/mcpdev80/baseharbor-node-connector/internal/runtime/quadlet"
)

// RuntimeRealizer is the bounded connector-side realization surface.
// BaseHarbor Core decides what should exist; the connector only performs an already
// authorized, typed realization operation on the target.
type RuntimeRealizer interface {
	PullImage(ctx context.Context, reference string) error
	Start(ctx context.Context, resourceID string) error
	Stop(ctx context.Context, resourceID string) error
	Restart(ctx context.Context, resourceID string) error
	Remove(ctx context.Context, resourceID string, force bool) error
	EnsureVolume(ctx context.Context, name string) error
	RemoveVolume(ctx context.Context, name string, force bool) error
	EnsureNetwork(ctx context.Context, name, driver string) error
	RemoveNetwork(ctx context.Context, resourceID string) error
}

type ComposeRealizer interface {
	Apply(ctx context.Context, request compose.ApplyRequest) (compose.Result, error)
	Destroy(ctx context.Context, request compose.DestroyRequest) (compose.Result, error)
}

type QuadletRealizer interface {
	List(ctx context.Context) ([]quadlet.Entry, error)
	Apply(ctx context.Context, name, content string, enable bool) error
	Remove(ctx context.Context, name string) error
	Enable(ctx context.Context, name string) error
	Disable(ctx context.Context, name string) error
}

// Observation keeps inventory/inspect/log/exec concerns separate from realization.
type Observation interface {
	List(ctx context.Context) ([]container.Resource, error)
	Logs(ctx context.Context, resourceID string, options container.LogOptions) (string, error)
	Exec(ctx context.Context, resourceID string, request container.ExecRequest) (container.ExecResult, error)
}
