package health

import (
	"context"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
)

type Collector struct {
	kind   bhruntime.Kind
	runner execx.Runner
}

func NewCollector(kind bhruntime.Kind) *Collector {
	return &Collector{kind: kind, runner: execx.Runner{}}
}

func (c *Collector) Snapshot(ctx context.Context) Snapshot {
	now := time.Now().UTC()
	snapshot := Snapshot{
		ObservedAt:      now,
		Runtime:         string(c.kind),
		OperatingSystem: runtime.GOOS,
		Architecture:    runtime.GOARCH,
		CPUs:            runtime.NumCPU(),
	}

	command, err := c.kind.Command()
	if err != nil {
		return snapshot
	}

	if result, err := c.runner.Run(ctx, nil, command, "info", "--format", "{{json .}}"); err == nil {
		var info map[string]any
		if json.Unmarshal([]byte(result.Stdout), &info) == nil {
			snapshot.RuntimeVersion = firstString(info, "ServerVersion", "Version")
			snapshot.MemoryTotalBytes = uint64(firstInt64(info, "MemTotal"))
			snapshot.ContainersTotal = int(firstInt64(info, "Containers"))
			snapshot.ContainersRunning = int(firstInt64(info, "ContainersRunning"))
			snapshot.ImagesTotal = int(firstInt64(info, "Images"))
		}
	}

	return snapshot
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		switch value := values[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case float64:
			return strconv.FormatFloat(value, 'f', -1, 64)
		}
	}
	return ""
}

func firstInt64(values map[string]any, keys ...string) int64 {
	for _, key := range keys {
		switch value := values[key].(type) {
		case float64:
			return int64(value)
		case string:
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}
