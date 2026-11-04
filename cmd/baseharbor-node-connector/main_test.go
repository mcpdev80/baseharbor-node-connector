package main

import (
	"bytes"
	"context"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigDerivesStableIdentityAndPrivatePaths(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("BASEHARBOR_CONNECTOR_CORE", "")
	t.Setenv("BASEHARBOR_CONNECTOR_TARGET_ID", "")
	t.Setenv("BASEHARBOR_CONNECTOR_NODE_ID", "")

	var stderr bytes.Buffer
	cfg, err := parseConfig([]string{
		"--tenant-id", "11111111-1111-4111-8111-111111111111",
		"--core", "core.example:9443",
		"--target-id", "edge-a",
		"--node-id", "node-1",
		"--runtime", "podman",
	}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "core.example" {
		t.Fatalf("server name = %q", cfg.ServerName)
	}
	if cfg.Runtime != "podman" {
		t.Fatal("explicit enrolled runtime was lost")
	}
	if cfg.NodeIdentity != "spiffe://baseharbor/platform/connectors/11111111-1111-4111-8111-111111111111/edge-a/node-1" {
		t.Fatalf("node identity = %q", cfg.NodeIdentity)
	}
	if !strings.HasSuffix(cfg.PrivateKeyFile, filepath.Join("identity", "node.key")) {
		t.Fatalf("private key path = %q", cfg.PrivateKeyFile)
	}
}

func TestParseConfigRejectsAmbiguousIdentitySegments(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var stderr bytes.Buffer
	_, err := parseConfig([]string{
		"--tenant-id", "11111111-1111-4111-8111-111111111111",
		"--core", "core.example:9443",
		"--target-id", "../escape",
		"--node-id", "node-1",
	}, &stderr)
	if err == nil {
		t.Fatal("invalid target identity unexpectedly accepted")
	}
}

func TestNeedsEnrollmentRequiresAllIdentityMaterial(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		filepath.Join(dir, "node.crt"),
		filepath.Join(dir, "node.key"),
		filepath.Join(dir, "ca.pem"),
	}
	for _, path := range files {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if needsEnrollment(testTLSFiles(files)) {
		t.Fatal("complete identity material unexpectedly requires enrollment")
	}
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	if !needsEnrollment(testTLSFiles(files)) {
		t.Fatal("missing identity material did not require enrollment")
	}
}

func TestCertificateRenewalRequiresExplicitAuthorizationExchange(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("BASEHARBOR_CONNECTOR_BOOTSTRAP_URL", "")
	base := []string{"--tenant-id", "11111111-1111-4111-8111-111111111111", "--core", "core.example:9443",
		"--target-id", "edge-a", "--node-id", "node-a", "--renew-certificate"}
	if _, err := parseConfig(base, &bytes.Buffer{}); err == nil {
		t.Fatal("renewal silently reused the established session instead of a fresh authorization")
	}
	cfg, err := parseConfig(append(base, "--bootstrap-url", "https://core.example/api/v1/connectors/enroll"), &bytes.Buffer{})
	if err != nil || !cfg.RenewCertificate || cfg.NodeID != "node-a" || cfg.TargetID != "edge-a" {
		t.Fatal("renewal changed stable enrollment identity", err)
	}
}

func testTLSFiles(files []string) targetaccess.TLSFiles {
	return targetaccess.TLSFiles{
		CertificateFile: files[0],
		PrivateKeyFile:  files[1],
		TrustBundleFile: files[2],
	}
}

// The service subcommand exposes an executable lifecycle path and fails closed
// when the unit is not self-owned to the connector binary identity.
func TestServiceSubcommandRejectsForeignUnit(t *testing.T) {
	dir := t.TempDir()
	var stderr bytes.Buffer
	err := serviceRun(context.Background(), []string{"--unit", "foreign-unit.container", "--state-root", dir, "--op", "install"}, &stderr)
	if err == nil {
		t.Fatal("service install of a foreign unit must be rejected")
	}
}

// The service subcommand requires an op and a self-owned unit; missing fields are
// rejected before any lifecycle runs.
func TestServiceSubcommandRequiresOpAndSelfOwnedUnit(t *testing.T) {
	dir := t.TempDir()
	var stderr bytes.Buffer
	if err := serviceRun(context.Background(), []string{"--unit", "baseharbor-node-connector.podman.container", "--state-root", dir}, &stderr); err == nil {
		t.Fatal("service without --op must be rejected")
	}
	if err := serviceRun(context.Background(), []string{"--op", "install", "--state-root", dir}, &stderr); err == nil {
		t.Fatal("service without --unit must be rejected")
	}
}

// The direct-launch owner-binding guard accepts a blank unit (ad-hoc launch) and
// a unit that references the connector binary; it fails closed on any foreign
// unit name so the connector can never run under a unit it does not own.
func TestEnforceSelfOwnedUnitFailsClosedOnForeignUnit(t *testing.T) {
	if err := enforceSelfOwnedUnit(""); err != nil {
		t.Fatalf("blank unit (ad-hoc launch) must be allowed, got: %v", err)
	}
	if err := enforceSelfOwnedUnit("baseharbor-node-connector.podman.container"); err != nil {
		t.Fatalf("connector-owned unit must be allowed, got: %v", err)
	}
	if err := enforceSelfOwnedUnit("foreign-core.service"); err == nil {
		t.Fatal("foreign unit must be rejected by the owner-binding guard")
	}
}

// The rendered ExecStart for the connector's own unit carries the
// --self-owned-unit flag and the connector accepts its own unit name through
// the guard, proving the shipped ExecStart is executable.
func TestExecLineCarriesSelfOwnedUnitFlagAndOwnUnitPasses(t *testing.T) {
	line := execLineFor("baseharbor-node-connector.podman.container")
	if !strings.Contains(line, "--self-owned-unit") {
		t.Fatalf("ExecStart must carry the --self-owned-unit flag, got: %q", line)
	}
	if err := enforceSelfOwnedUnit("baseharbor-node-connector.podman.container"); err != nil {
		t.Fatalf("own unit from ExecStart must pass the guard, got: %v", err)
	}
}
