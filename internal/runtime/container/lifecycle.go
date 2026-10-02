package container

import (
	"context"
	"fmt"
	"strings"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
)

type Lifecycle struct {
	runtime bhruntime.Kind
	runner  execx.Runner
}

func NewLifecycle(kind bhruntime.Kind) *Lifecycle {
	return &Lifecycle{runtime: kind, runner: execx.Runner{}}
}

func (l *Lifecycle) run(ctx context.Context, args ...string) error {
	command, err := l.runtime.Command()
	if err != nil {
		return err
	}
	_, err = l.runner.Run(ctx, nil, command, args...)
	return err
}

func (l *Lifecycle) Start(ctx context.Context, id string) error {
	if err := validateResourceID(id); err != nil {
		return err
	}
	return l.run(ctx, "start", id)
}

func (l *Lifecycle) Stop(ctx context.Context, id string) error {
	if err := validateResourceID(id); err != nil {
		return err
	}
	return l.run(ctx, "stop", id)
}

func (l *Lifecycle) Restart(ctx context.Context, id string) error {
	if err := validateResourceID(id); err != nil {
		return err
	}
	return l.run(ctx, "restart", id)
}

func (l *Lifecycle) Remove(ctx context.Context, id string, force bool) error {
	if err := validateResourceID(id); err != nil {
		return err
	}
	args := []string{"rm"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, id)
	return l.run(ctx, args...)
}

func (l *Lifecycle) PullImage(ctx context.Context, reference string) error {
	if hasControlCharacter(reference) {
		return fmt.Errorf("invalid image reference")
	}
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return fmt.Errorf("invalid image reference")
	}
	return l.run(ctx, "pull", reference)
}

func (l *Lifecycle) EnsureVolume(ctx context.Context, name string) error {
	if err := validateResourceName(name); err != nil {
		return err
	}
	return l.run(ctx, "volume", "create", name)
}

func (l *Lifecycle) RemoveVolume(ctx context.Context, name string, force bool) error {
	if err := validateResourceName(name); err != nil {
		return err
	}
	args := []string{"volume", "rm"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, name)
	return l.run(ctx, args...)
}

func (l *Lifecycle) EnsureNetwork(ctx context.Context, name, driver string) error {
	if err := validateResourceName(name); err != nil {
		return err
	}
	if hasControlCharacter(driver) {
		return fmt.Errorf("invalid network driver")
	}
	driver = strings.TrimSpace(driver)
	args := []string{"network", "create"}
	if driver != "" {
		args = append(args, "--driver", driver)
	}
	args = append(args, name)
	return l.run(ctx, args...)
}

func (l *Lifecycle) RemoveNetwork(ctx context.Context, id string) error {
	if err := validateResourceID(id); err != nil {
		return err
	}
	return l.run(ctx, "network", "rm", id)
}

func validateResourceName(name string) error {
	if hasControlCharacter(name) {
		return fmt.Errorf("invalid resource name")
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf("invalid resource name")
	}
	return nil
}
