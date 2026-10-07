package quadlet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/mcpdev80/baseharbor-node-connector/internal/fssecure"
)

type executionBinding struct {
	SourceSHA256    string `json:"source_sha256"`
	BootID          string `json:"boot_id"`
	NotBeforeMicros uint64 `json:"not_before_micros"`
}

func executionBindingName(name string) string {
	return filepath.Join(name+".d", "98-baseharbor-execution.json")
}

func sourceDigest(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

// bindPublishedExecution records the exact resolved source and a boot-scoped
// monotonic lower bound before restart. A failed/lost mutation cannot turn the
// previous execution into proof for the newly published source.
// The caller holds the manager operation lock.
func (m *Manager) bindPublishedExecution(ctx context.Context, name, content string) error {
	// No execution receipt may be written alongside a foreign source or
	// activation artifact, even when its native container is absent.
	for _, artifact := range []string{name, filepath.Join(name+".d", "99-baseharbor-activation.conf"), executionBindingName(name)} {
		if _, err := os.Lstat(filepath.Join(m.baseDir, artifact)); err == nil {
			if err := m.verifyOwned(artifact); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	boot, notBefore, err := executionClock()
	if err != nil || notBefore == 0 {
		return errors.New("native execution binding is unavailable")
	}
	data, err := json.Marshal(executionBinding{sourceDigest(content), boot, notBefore})
	if err != nil {
		return err
	}
	return m.writeOwned(ctx, executionBindingName(name), data)
}

// VerifyPublishedCompletion requires both current unit ownership and evidence
// of successful execution after this exact source's explicit activation. Mere
// inactive/success state from an older run never qualifies a changed bundle.
func (m *Manager) VerifyPublishedCompletion(ctx context.Context, root *fssecure.Root, directory, name, content string) error {
	observed, err := m.ObservePublished(ctx, root, directory, name, content)
	if err != nil {
		return err
	}
	release, err := m.acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	// Revalidate source after reacquiring the lock: publication may have
	// changed between observation and the execution receipt read.
	resolved, err := resolvePublishedContent(root, directory, name, content)
	if err != nil || m.verifyOwned(name) != nil {
		return errors.New("completion source ownership is unavailable")
	}
	actual, err := os.ReadFile(filepath.Join(m.baseDir, name))
	if err != nil || string(actual) != resolved {
		return errors.New("completion source changed during observation")
	}
	receipt := executionBindingName(name)
	if err := m.verifyOwned(receipt); err != nil {
		return errors.New("native execution binding is unverified")
	}
	data, err := os.ReadFile(filepath.Join(m.baseDir, receipt))
	var binding executionBinding
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &binding) != nil {
		return errors.New("native execution binding is invalid")
	}
	boot, now, err := executionClock()
	if err != nil || binding.BootID != boot || binding.SourceSHA256 != sourceDigest(resolved) ||
		binding.NotBeforeMicros == 0 || binding.NotBeforeMicros > now ||
		observed.StartedMicros < binding.NotBeforeMicros || observed.FinishedMicros < observed.StartedMicros ||
		observed.FinishedMicros == 0 || observed.FinishedMicros > now ||
		observed.ExitKind != 1 || observed.ExitCode != 0 || observed.Result != "success" ||
		!((observed.ActiveState == "inactive" && observed.SubState == "dead") || (observed.ActiveState == "active" && observed.SubState == "exited")) {
		return errors.New("successful execution of the current published source is unverified")
	}
	return nil
}
