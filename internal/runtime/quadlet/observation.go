package quadlet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

type UnitObservation struct {
	Name           string    `json:"name"`
	Unit           string    `json:"unit"`
	ActiveState    string    `json:"active_state"`
	SubState       string    `json:"sub_state"`
	Result         string    `json:"result"`
	ExitKind       int       `json:"exit_kind"`
	ExitCode       int       `json:"exit_code"`
	StartedMicros  uint64    `json:"started_micros"`
	FinishedMicros uint64    `json:"finished_micros"`
	ObservedAt     time.Time `json:"observed_at"`
}

// ObservePublished only observes a loaded service whose source still matches
// the exact immutable Core bundle and this manager's ownership receipt.
func (m *Manager) ObservePublished(ctx context.Context, root *fssecure.Root, directory, name, content string) (UnitObservation, error) {
	file, unit, err := m.resolve(name)
	if err != nil || filepath.Ext(name) != ".container" {
		return UnitObservation{}, errors.New("invalid completion unit selection")
	}
	expected, err := resolvePublishedContent(root, directory, name, content)
	if err != nil {
		return UnitObservation{}, err
	}
	release, err := m.acquire(ctx)
	if err != nil {
		return UnitObservation{}, err
	}
	defer release()
	if err := m.verifyOwned(name); err != nil {
		return UnitObservation{}, err
	}
	actual, err := os.ReadFile(file)
	if err != nil || string(actual) != expected {
		return UnitObservation{}, errors.New("loaded completion source differs from immutable Core bundle")
	}
	if err := m.checkPublishedNativeOwnership(ctx, name, expected); err != nil {
		return UnitObservation{}, err
	}
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	properties := "Id,LoadState,SourcePath,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic"
	result, err := m.runner.Run(probe, nil, "systemctl", "--user", "show", "--property="+properties, unit)
	if err != nil {
		return UnitObservation{}, errors.New("native completion unit observation is unavailable")
	}
	return parseUnitObservation(name, unit, file, result.Stdout)
}

func parseUnitObservation(name, unit, source, data string) (UnitObservation, error) {
	invalid := errors.New("native completion unit evidence is incomplete or differs")
	if len(data) > 16384 {
		return UnitObservation{}, invalid
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return UnitObservation{}, invalid
		}
		if _, duplicate := fields[key]; duplicate {
			return UnitObservation{}, invalid
		}
		fields[key] = value
	}
	for _, key := range []string{"Id", "LoadState", "SourcePath", "ActiveState", "SubState", "Result", "ExecMainCode", "ExecMainStatus", "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic"} {
		if _, ok := fields[key]; !ok {
			return UnitObservation{}, invalid
		}
	}
	if len(fields) != 10 || fields["Id"] != unit || fields["LoadState"] != "loaded" || fields["SourcePath"] != source {
		return UnitObservation{}, invalid
	}
	exitKind, err := strconv.Atoi(fields["ExecMainCode"])
	if err != nil || exitKind < 0 || exitKind > 6 {
		return UnitObservation{}, invalid
	}
	exitCode, err := strconv.Atoi(fields["ExecMainStatus"])
	if err != nil || exitCode < 0 || exitCode > 255 {
		return UnitObservation{}, invalid
	}
	started, err := strconv.ParseUint(fields["ExecMainStartTimestampMonotonic"], 10, 64)
	if err != nil {
		return UnitObservation{}, invalid
	}
	finished, err := strconv.ParseUint(fields["ExecMainExitTimestampMonotonic"], 10, 64)
	if err != nil {
		return UnitObservation{}, invalid
	}
	return UnitObservation{Name: name, Unit: unit, ActiveState: fields["ActiveState"], SubState: fields["SubState"], Result: fields["Result"], ExitKind: exitKind, ExitCode: exitCode, StartedMicros: started, FinishedMicros: finished, ObservedAt: time.Now().UTC()}, nil
}
