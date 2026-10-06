package connector

import (
	"testing"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

func TestOutboundPoolDefaultsToBoundedParallelSessions(t *testing.T) {
	cfg := OutboundPoolConfig{Sessions: 0}
	if got := cfg.sessionCount(); got != defaultOutboundSessions {
		t.Fatalf("session count = %d, want %d", got, defaultOutboundSessions)
	}
}

func TestOutboundPoolRejectsExcessiveSessionCount(t *testing.T) {
	cfg := OutboundPoolConfig{
		OutboundConfig: OutboundConfig{
			Address: "core.example:9443",
			TLS: targetaccess.TLSFiles{
				CertificateFile:      "node.crt",
				PrivateKeyFile:       "node.key",
				TrustBundleFile:      "ca.pem",
				ExpectedPeerIdentity: "spiffe://baseharbor/platform/core/control-plane",
			},
		},
		Sessions: maxOutboundSessions + 1,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("excessive outbound session count unexpectedly accepted")
	}
}
