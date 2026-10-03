package connector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

type OutboundConfig struct {
	Address          string
	TLS              targetaccess.TLSFiles
	ReconnectInitial time.Duration
	ReconnectMax     time.Duration
	DialTimeout      time.Duration
	MaxFrameBytes    uint32
}

func (c OutboundConfig) Validate() error {
	if strings.TrimSpace(c.Address) == "" {
		return errors.New("core address is required")
	}
	if err := c.TLS.Validate(); err != nil {
		return fmt.Errorf("target access TLS: %w", err)
	}
	if c.ReconnectInitial < 0 || c.ReconnectMax < 0 || c.DialTimeout < 0 {
		return errors.New("outbound timing values must not be negative")
	}
	return nil
}

func (a *TargetAccess) RunOutboundControl(ctx context.Context, cfg OutboundConfig) error {
	if a == nil {
		return errors.New("target access service is required")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	initial := cfg.ReconnectInitial
	if initial == 0 {
		initial = time.Second
	}
	maxBackoff := cfg.ReconnectMax
	if maxBackoff == 0 {
		maxBackoff = 30 * time.Second
	}
	if maxBackoff < initial {
		maxBackoff = initial
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 10 * time.Second
	}

	backoff := initial
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := a.runOutboundControlOnce(ctx, cfg, dialTimeout)
		if err == nil {
			backoff = initial
		}
		if err := waitReconnect(ctx, backoff); err != nil {
			return err
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func (a *TargetAccess) runOutboundControlOnce(ctx context.Context, cfg OutboundConfig, dialTimeout time.Duration) error {
	dialer := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("dial BaseHarbor Core: %w", err)
	}

	session, err := targetaccess.OpenSession(
		ctx,
		conn,
		targetaccess.TLSClient,
		cfg.TLS,
		targetaccess.Hello{
			ContractVersions: []string{targetaccess.ContractVersion},
			ProtocolVersions: []string{targetaccess.ProtocolVersion},
			Node:             a.identity,
		},
		cfg.MaxFrameBytes,
	)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer session.Close()

	if err := a.ServeSession(ctx, session); err != nil {
		return fmt.Errorf("serve outbound target access session: %w", err)
	}
	return nil
}

func waitReconnect(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
