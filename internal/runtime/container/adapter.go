package container

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
)

// Adapter exposes only bounded container operations needed by the Target Access contract.
// It deliberately does not provide arbitrary runtime-command execution.
type Adapter struct {
	runtime bhruntime.Kind
	runner  execx.Runner
}

func NewAdapter(kind bhruntime.Kind) *Adapter {
	return &Adapter{runtime: kind, runner: execx.Runner{}}
}

func (a *Adapter) command() (string, error) {
	return a.runtime.Command()
}

func (a *Adapter) List(ctx context.Context) ([]Resource, error) {
	command, err := a.command()
	if err != nil {
		return nil, err
	}

	stats := map[string]Resource{}
	if result, err := a.runner.Run(ctx, nil, command,
		"stats", "--no-stream", "--format",
		"{{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}",
	); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
			parts := strings.Split(line, "\t")
			if len(parts) < 4 {
				continue
			}
			stats[strings.TrimSpace(parts[0])] = Resource{
				CPUPercent:  strings.TrimSpace(parts[1]),
				MemoryUsage: strings.TrimSpace(parts[2]),
				NetworkIO:   strings.TrimSpace(parts[3]),
			}
		}
	}

	result, err := a.runner.Run(ctx, nil, command,
		"ps", "-a", "--format",
		"{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}\t{{.CreatedAt}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Label \"io.podman.systemd.unit\"}}\t{{.Label \"PODMAN_SYSTEMD_UNIT\"}}",
	)
	if err != nil {
		return nil, err
	}

	var resources []Resource
	if strings.TrimSpace(result.Stdout) == "" {
		return resources, nil
	}

	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			continue
		}
		resource := Resource{
			ID:      strings.TrimSpace(parts[0]),
			Name:    strings.TrimSpace(parts[1]),
			Image:   strings.TrimSpace(parts[2]),
			Status:  strings.TrimSpace(parts[3]),
			State:   strings.TrimSpace(parts[4]),
			Created: strings.TrimSpace(parts[6]),
		}
		if ports := strings.TrimSpace(parts[5]); ports != "" {
			resource.Ports = strings.Split(ports, ", ")
		}
		if len(parts) > 7 {
			resource.ComposeProject = strings.TrimSpace(parts[7])
		}
		if len(parts) > 8 {
			resource.ComposeService = strings.TrimSpace(parts[8])
		}
		if len(parts) > 9 {
			resource.QuadletUnit = strings.TrimSpace(parts[9])
		}
		if resource.QuadletUnit == "" && len(parts) > 10 {
			resource.QuadletUnit = strings.TrimSpace(parts[10])
		}
		for id, stat := range stats {
			if id == resource.ID || strings.HasPrefix(resource.ID, id) || strings.HasPrefix(id, resource.ID) {
				resource.CPUPercent = stat.CPUPercent
				resource.MemoryUsage = stat.MemoryUsage
				resource.NetworkIO = stat.NetworkIO
				break
			}
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func (a *Adapter) Logs(ctx context.Context, id string, options LogOptions) (string, error) {
	if err := validateResourceID(id); err != nil {
		return "", err
	}
	command, err := a.command()
	if err != nil {
		return "", err
	}
	args := []string{"logs"}
	if options.Tail > 0 {
		args = append(args, "--tail", strconv.Itoa(options.Tail))
	}
	if strings.TrimSpace(options.Since) != "" {
		args = append(args, "--since", strings.TrimSpace(options.Since))
	}
	args = append(args, id)
	result, err := a.runner.Run(ctx, nil, command, args...)
	if err != nil {
		return "", err
	}
	return result.Stdout, nil
}

func (a *Adapter) Inspect(ctx context.Context, id string) (json.RawMessage, error) {
	if err := validateResourceID(id); err != nil {
		return nil, err
	}
	command, err := a.command()
	if err != nil {
		return nil, err
	}
	result, err := a.runner.Run(ctx, nil, command, "inspect", id)
	if err != nil {
		return nil, err
	}
	raw := json.RawMessage(result.Stdout)
	if !json.Valid(raw) {
		return nil, fmt.Errorf("runtime returned invalid inspect JSON")
	}
	return raw, nil
}

func (a *Adapter) Exec(ctx context.Context, id string, request ExecRequest) (ExecResult, error) {
	if err := validateResourceID(id); err != nil {
		return ExecResult{}, err
	}
	if len(request.Argv) == 0 {
		return ExecResult{}, fmt.Errorf("argv is required")
	}
	for _, arg := range request.Argv {
		if strings.ContainsRune(arg, '\x00') {
			return ExecResult{}, fmt.Errorf("argv contains NUL")
		}
	}

	command, err := a.command()
	if err != nil {
		return ExecResult{}, err
	}

	args := []string{"exec"}
	for key, value := range request.Environment {
		if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "=\x00\r\n") {
			return ExecResult{}, fmt.Errorf("invalid environment key")
		}
		args = append(args, "--env", key+"="+value)
	}
	if strings.TrimSpace(request.Workdir) != "" {
		args = append(args, "--workdir", request.Workdir)
	}
	args = append(args, id)
	args = append(args, request.Argv...)

	execCtx := ctx
	if request.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, time.Duration(request.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	result, err := a.runner.Run(execCtx, nil, command, args...)
	response := ExecResult{
		Stdout: result.Stdout,
		Stderr: result.Stderr,
		ExitCode: result.ExitCode,
	}
	if err != nil {
		return response, err
	}
	return response, nil
}

func validateResourceID(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("resource id is required")
	}
	if strings.ContainsAny(id, "\x00\r\n") {
		return fmt.Errorf("invalid resource id")
	}
	return nil
}
