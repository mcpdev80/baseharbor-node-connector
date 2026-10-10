package compose

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

var phaseService = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Recheck effective declared services through read-only Compose configuration.
// A selected phase cannot build source, remove siblings or start dependencies.
func (a *Adapter) verifyPhase(ctx context.Context, req ApplyRequest, command string, args []string) error {
	if len(req.Services) == 0 || len(req.Services) > 64 || req.Build || req.RemoveOrphans {
		return errors.New("invalid scoped Compose activation phase")
	}
	seen := map[string]bool{}
	for _, service := range req.Services {
		if !phaseService.MatchString(service) || seen[service] {
			return errors.New("invalid Compose phase service")
		}
		seen[service] = true
	}
	configArgs := append(append([]string(nil), args...), "config", "--services")
	result, err := a.run(ctx, 30, command, configArgs...)
	if err != nil || result.ExitCode != 0 {
		return errors.New("Compose phase configuration is unavailable")
	}
	declared := map[string]bool{}
	for _, service := range strings.Fields(result.Stdout) {
		declared[service] = true
	}
	for _, service := range req.Services {
		if !declared[service] {
			return errors.New("Compose phase selects an undeclared service")
		}
	}
	return nil
}
