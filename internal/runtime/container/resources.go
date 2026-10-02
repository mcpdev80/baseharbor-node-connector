package container

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
)

type Image struct {
	ID           string `json:"id"`
	Reference    string `json:"reference"`
	Size         string `json:"size,omitempty"`
	CreatedSince string `json:"created_since,omitempty"`
	InUse        bool   `json:"in_use"`
}

type Volume struct {
	Name               string `json:"name"`
	Driver             string `json:"driver,omitempty"`
	Scope              string `json:"scope,omitempty"`
	InUse              bool   `json:"in_use"`
	AttachedContainers int    `json:"attached_containers"`
}

type Network struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Driver             string `json:"driver,omitempty"`
	Scope              string `json:"scope,omitempty"`
	InUse              bool   `json:"in_use"`
	AttachedContainers int    `json:"attached_containers"`
}

type Resources struct {
	runtime bhruntime.Kind
	runner  execx.Runner
}

func NewResources(kind bhruntime.Kind) *Resources {
	return &Resources{runtime: kind, runner: execx.Runner{}}
}

func (r *Resources) command() (string, error) {
	return r.runtime.Command()
}

func (r *Resources) Images(ctx context.Context) ([]Image, error) {
	command, err := r.command()
	if err != nil {
		return nil, err
	}
	result, err := r.runner.Run(ctx, nil, command, "images", "--format", "{{.ID}}\t{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}")
	if err != nil {
		return nil, err
	}

	usedRefs := map[string]struct{}{}
	usedIDs := map[string]struct{}{}

	if containers, err := r.runner.Run(ctx, nil, command, "ps", "-a", "--format", "{{.Image}}"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(containers.Stdout), "\n") {
			ref := strings.TrimSpace(line)
			if ref == "" {
				continue
			}
			usedRefs[ref] = struct{}{}
			if !strings.Contains(ref, ":") {
				usedRefs[ref+":latest"] = struct{}{}
			}
		}
	}

	if idsResult, err := r.runner.Run(ctx, nil, command, "ps", "-aq"); err == nil {
		ids := strings.Fields(idsResult.Stdout)
		if len(ids) > 0 {
			args := []string{"inspect", "--format", "{{.Image}}\t{{.Config.Image}}"}
			args = append(args, ids...)
			if inspect, err := r.runner.Run(ctx, nil, command, args...); err == nil {
				for _, line := range strings.Split(strings.TrimSpace(inspect.Stdout), "\n") {
					parts := strings.Split(line, "\t")
					if len(parts) > 0 {
						id := strings.TrimPrefix(strings.TrimSpace(parts[0]), "sha256:")
						if id != "" {
							usedIDs[id] = struct{}{}
						}
					}
					if len(parts) > 1 {
						ref := strings.TrimSpace(parts[1])
						if ref != "" {
							usedRefs[ref] = struct{}{}
							if !strings.Contains(ref, ":") {
								usedRefs[ref+":latest"] = struct{}{}
							}
						}
					}
				}
			}
		}
	}

	images := make([]Image, 0)
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		image := Image{ID: strings.TrimSpace(parts[0]), Reference: strings.TrimSpace(parts[1])}
		if len(parts) > 2 {
			image.Size = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			image.CreatedSince = strings.TrimSpace(parts[3])
		}
		image.InUse = imageReferenceInUse(usedRefs, usedIDs, image.ID, image.Reference)
		images = append(images, image)
	}
	return images, nil
}

func (r *Resources) Volumes(ctx context.Context) ([]Volume, error) {
	command, err := r.command()
	if err != nil {
		return nil, err
	}
	result, err := r.runner.Run(ctx, nil, command, "volume", "ls", "--format", "{{.Name}}\t{{.Driver}}\t{{.Scope}}")
	if err != nil {
		return nil, err
	}

	usage := map[string]int{}
	if idsResult, err := r.runner.Run(ctx, nil, command, "ps", "-aq"); err == nil {
		ids := strings.Fields(idsResult.Stdout)
		if len(ids) > 0 {
			args := []string{"inspect", "--format", "{{json .Mounts}}"}
			args = append(args, ids...)
			if inspect, err := r.runner.Run(ctx, nil, command, args...); err == nil {
				for _, line := range strings.Split(strings.TrimSpace(inspect.Stdout), "\n") {
					var mounts []map[string]any
					if json.Unmarshal([]byte(line), &mounts) != nil {
						continue
					}
					for _, mount := range mounts {
						if kind, _ := mount["Type"].(string); kind != "volume" {
							continue
						}
						name, _ := mount["Name"].(string)
						name = strings.TrimSpace(name)
						if name != "" {
							usage[name]++
						}
					}
				}
			}
		}
	}

	volumes := make([]Volume, 0)
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		name := strings.TrimSpace(parts[0])
		volume := Volume{Name: name, AttachedContainers: usage[name], InUse: usage[name] > 0}
		if len(parts) > 1 {
			volume.Driver = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			volume.Scope = strings.TrimSpace(parts[2])
		}
		volumes = append(volumes, volume)
	}
	return volumes, nil
}

func (r *Resources) Networks(ctx context.Context) ([]Network, error) {
	command, err := r.command()
	if err != nil {
		return nil, err
	}
	result, err := r.runner.Run(ctx, nil, command, "network", "ls", "--format", "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}")
	if err != nil {
		return nil, err
	}

	usage := map[string]int{}
	if containers, err := r.runner.Run(ctx, nil, command, "ps", "-a", "--format", "{{json .}}"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(containers.Stdout), "\n") {
			var entry map[string]any
			if json.Unmarshal([]byte(line), &entry) != nil {
				continue
			}
			field, _ := entry["Networks"].(string)
			for _, raw := range strings.Split(field, ",") {
				name := strings.TrimSpace(raw)
				if name != "" {
					usage[name]++
				}
			}
		}
	}

	networks := make([]Network, 0)
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		network := Network{
			ID: strings.TrimSpace(parts[0]), Name: name,
			AttachedContainers: usage[name], InUse: usage[name] > 0,
		}
		if len(parts) > 2 {
			network.Driver = strings.TrimSpace(parts[2])
		}
		if len(parts) > 3 {
			network.Scope = strings.TrimSpace(parts[3])
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func imageReferenceInUse(refs, ids map[string]struct{}, imageID, ref string) bool {
	imageID = strings.TrimPrefix(strings.TrimSpace(imageID), "sha256:")
	if _, ok := ids[imageID]; ok {
		return true
	}
	if _, ok := refs[ref]; ok {
		return true
	}
	if strings.HasSuffix(ref, ":latest") {
		_, ok := refs[strings.TrimSuffix(ref, ":latest")]
		return ok
	}
	return false
}
