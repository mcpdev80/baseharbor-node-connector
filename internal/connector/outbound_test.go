package connector

import (
	"testing"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func TestOutboundConfigRequiresExplicitCoreAndMTLSIdentity(t *testing.T) {
	cfg := OutboundConfig{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("empty outbound configuration unexpectedly accepted")
	}

	cfg = OutboundConfig{
		Address: "core.example:9443",
		TLS: targetaccess.TLSFiles{
			CertificateFile:      "node.crt",
			PrivateKeyFile:       "node.key",
			TrustBundleFile:      "ca.pem",
			ExpectedPeerIdentity: "spiffe://baseharbor/platform/core/control-plane",
			ServerName:           "core.example",
		},
		DialTimeout: 5 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid outbound config rejected: %v", err)
	}
}

func TestOutboundConfigRejectsNegativeTiming(t *testing.T) {
	cfg := OutboundConfig{
		Address: "core.example:9443",
		TLS: targetaccess.TLSFiles{
			CertificateFile:      "node.crt",
			PrivateKeyFile:       "node.key",
			TrustBundleFile:      "ca.pem",
			ExpectedPeerIdentity: "spiffe://baseharbor/platform/core/control-plane",
		},
		ReconnectInitial: -time.Second,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("negative reconnect delay unexpectedly accepted")
	}
}

func TestReconnectDelayNeverOverflows(t *testing.T) {
	for _, tc := range []struct {
		name string
		current time.Duration
		maximum time.Duration
		want time.Duration
	}{
		{name: "normal", current: time.Second, maximum: 30 * time.Second, want: 2 * time.Second},
		{name: "cap", current: 20 * time.Second, maximum: 30 * time.Second, want: 30 * time.Second},
		{name: "at-cap", current: 30 * time.Second, maximum: 30 * time.Second, want: 30 * time.Second},
		{name: "huge-overflow", current: time.Duration(1 << 62), maximum: time.Duration(1<<63 - 1), want: time.Duration(1<<63 - 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := nextReconnectDelay(tc.current, tc.maximum)
			if got != tc.want {
				t.Fatalf("next reconnect delay = %v, want %v", got, tc.want)
			}
		})
	}
}
