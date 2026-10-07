package compose

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
)

type ApplyRequest struct {
	ProjectDirectory string   `json:"project_directory"`
	Files            []string `json:"files"`
	EnvFile          string   `json:"env_file,omitempty"`
	Build            bool     `json:"build,omitempty"`
	ForceRecreate    bool     `json:"force_recreate,omitempty"`
	RemoveOrphans    bool     `json:"remove_orphans,omitempty"`
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
}

type DestroyRequest struct {
	ProjectDirectory string   `json:"project_directory"`
	Files            []string `json:"files"`
	EnvFile          string   `json:"env_file,omitempty"`
	RemoveOrphans    bool     `json:"remove_orphans,omitempty"`
	Volumes          bool     `json:"volumes,omitempty"`
	TimeoutSeconds   int      `json:"timeout_seconds,omitempty"`
}

type Result struct {
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode int    `json:"exit_code"`
}

type Adapter struct {
	runtime bhruntime.Kind
	staging *fssecure.Root
	runner  execx.Runner
}

func NewAdapter(kind bhruntime.Kind, staging *fssecure.Root) *Adapter {
	return &Adapter{runtime: kind, staging: staging, runner: execx.Runner{}}
}

func (a *Adapter) Apply(ctx context.Context, req ApplyRequest) (Result, error) {
	project, files, envFile, err := a.resolve(req.ProjectDirectory, req.Files, req.EnvFile)
	if err != nil {
		return Result{}, err
	}
	command, err := a.runtime.Command()
	if err != nil {
		return Result{}, err
	}

	args := []string{"compose", "--project-directory", project}
	for _, file := range files {
		args = append(args, "-f", file)
	}
	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}
	args = append(args, "up", "-d")
	if req.Build {
		args = append(args, "--build")
	}
	if req.ForceRecreate {
		args = append(args, "--force-recreate")
	}
	if req.RemoveOrphans {
		args = append(args, "--remove-orphans")
	}
	return a.run(ctx, req.TimeoutSeconds, command, args...)
}

func (a *Adapter) Destroy(ctx context.Context, req DestroyRequest) (Result, error) {
	project, files, envFile, err := a.resolve(req.ProjectDirectory, req.Files, req.EnvFile)
	if err != nil {
		return Result{}, err
	}
	command, err := a.runtime.Command()
	if err != nil {
		return Result{}, err
	}

	args := []string{"compose", "--project-directory", project}
	for _, file := range files {
		args = append(args, "-f", file)
	}
	if envFile != "" {
		args = append(args, "--env-file", envFile)
	}
	args = append(args, "down")
	if req.RemoveOrphans {
		args = append(args, "--remove-orphans")
	}
	if req.Volumes {
		args = append(args, "--volumes")
	}
	return a.run(ctx, req.TimeoutSeconds, command, args...)
}

func (a *Adapter) resolve(projectDirectory string, files []string, envFile string) (string, []string, string, error) {
	if a.staging == nil {
		return "", nil, "", fmt.Errorf("staging root is required")
	}
	members := append([]string(nil), files...)
	if envFile != "" {
		members = append(members, envFile)
	}
	if err := a.staging.VerifyPublishedBundle(projectDirectory, members...); err != nil {
		return "", nil, "", err
	}
	project, err := a.staging.Existing(projectDirectory)
	if err != nil {
		return "", nil, "", fmt.Errorf("resolve project directory: %w", err)
	}
	if len(files) == 0 {
		return "", nil, "", fmt.Errorf("at least one compose file is required")
	}
	resolvedFiles := make([]string, 0, len(files))
	for _, file := range files {
		resolved, err := a.staging.Existing(file)
		if err != nil {
			return "", nil, "", fmt.Errorf("resolve compose file: %w", err)
		}
		if ext := strings.ToLower(filepath.Ext(resolved)); ext != ".yml" && ext != ".yaml" {
			return "", nil, "", fmt.Errorf("unsupported compose file extension")
		}
		resolvedFiles = append(resolvedFiles, resolved)
	}
	resolvedEnv := ""
	if strings.TrimSpace(envFile) != "" {
		resolvedEnv, err = a.staging.Existing(envFile)
		if err != nil {
			return "", nil, "", fmt.Errorf("resolve env file: %w", err)
		}
	}
	return project, resolvedFiles, resolvedEnv, nil
}

func (a *Adapter) run(ctx context.Context, timeoutSeconds int, command string, args ...string) (Result, error) {
	runCtx := ctx
	if timeoutSeconds > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	}
	result, err := a.runner.Run(runCtx, nil, command, args...)
	out := Result{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode}
	return out, err
}
