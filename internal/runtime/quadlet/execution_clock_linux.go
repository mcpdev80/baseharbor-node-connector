//go:build linux

package quadlet

import (
	"errors"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

var bootIDPattern = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func executionClock() (string, uint64, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	boot := strings.TrimSpace(string(data))
	if err != nil || !bootIDPattern.MatchString(boot) {
		return "", 0, errors.New("native boot identity is unavailable")
	}
	var clock unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock); err != nil || clock.Sec < 0 || clock.Nsec < 0 {
		return "", 0, errors.New("native monotonic execution clock is unavailable")
	}
	return boot, uint64(clock.Sec)*1000000 + uint64(clock.Nsec)/1000, nil
}
