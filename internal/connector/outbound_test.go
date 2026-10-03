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
			ExpectedPeerIdentity: "spiffe://baseharbor/core/control-plane",
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
			ExpectedPeerIdentity: "spiffe://baseharbor/core/control-plane",
		},
		ReconnectInitial: -time.Second,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("negative reconnect delay unexpectedly accepted")
	}
}
