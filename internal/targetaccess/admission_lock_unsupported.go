//go:build !linux

package targetaccess

import (
	"context"
	"os"
)

func lockAdmissionFile(context.Context, *os.File) error {
	return ErrAdmissionJournal
}
