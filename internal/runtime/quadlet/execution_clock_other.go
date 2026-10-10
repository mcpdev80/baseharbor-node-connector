//go:build !linux

package quadlet

import "errors"

func executionClock() (string, uint64, error) {
	return "", 0, errors.New("native Quadlet execution evidence requires Linux")
}
