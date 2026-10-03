package connector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

const (
	defaultOutboundSessions = 4
	maxOutboundSessions     = 32
)

type OutboundPoolConfig struct {
	OutboundConfig
	Sessions int
}

func (c OutboundPoolConfig) Validate() error {
	if err := c.OutboundConfig.Validate(); err != nil {
		return err
	}
	if c.Sessions < 0 || c.Sessions > maxOutboundSessions {
		return fmt.Errorf("outbound sessions must be between 1 and %d", maxOutboundSessions)
	}
	return nil
}

func (c OutboundPoolConfig) sessionCount() int {
	if c.Sessions == 0 {
		return defaultOutboundSessions
	}
	return c.Sessions
}

func (a *TargetAccess) RunOutboundPool(ctx context.Context, cfg OutboundPoolConfig) error {
	if a == nil {
		return errors.New("target access service is required")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	workers := cfg.sessionCount()
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- a.runOutboundWorker(ctx, cfg.OutboundConfig)
		}()
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	for err := range errCh {
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return ctx.Err()
}

func (a *TargetAccess) runOutboundWorker(ctx context.Context, cfg OutboundConfig) error {
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
		if err := a.runOutboundAnyOnce(ctx, cfg, dialTimeout); err == nil {
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

func (a *TargetAccess) runOutboundAnyOnce(ctx context.Context, cfg OutboundConfig, dialTimeout time.Duration) error {
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
	if err := a.ServeAnySession(ctx, session); err != nil {
		return fmt.Errorf("serve pooled target access session: %w", err)
	}
	return nil
}
