package connector

import (
	"context"
	"errors"
	"io"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func (a *TargetAccess) ServeSession(ctx context.Context, session *targetaccess.Session) error {
	if a == nil {
		return errors.New("target access service is required")
	}
	if session == nil {
		return errors.New("target access session is required")
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var request targetaccess.Request
		if err := session.ReadRequest(&request); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		response := a.Execute(ctx, request)
		if err := session.WriteResponse(response); err != nil {
			return err
		}
	}
}
