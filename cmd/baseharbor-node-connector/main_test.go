package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
	"os"
	"os/exec"
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
	for _, test := range []struct {
		name    string
		unit    string
		wantErr bool
	}{
		{name: "ad-hoc", unit: ""},
		{name: "canonical podman", unit: "baseharbor-node-connector.podman.container"},
		{name: "canonical docker", unit: "baseharbor-node-connector.docker.container"},
		{name: "foreign", unit: "foreign-core.service", wantErr: true},
		{name: "foreign prefix", unit: "foreign-baseharbor-node-connector.podman.container", wantErr: true},
		{name: "foreign suffix", unit: "baseharbor-node-connector.podman.container.evil", wantErr: true},
		{name: "marker collision", unit: "foreign-baseharbor-node-connector.evil.container", wantErr: true},
		{name: "conflicting identity", unit: "baseharbor-node-connector.docker.container/baseharbor-node-connector.podman.container", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := enforceSelfOwnedUnit(test.unit)
			if test.wantErr && (err == nil || !strings.Contains(err.Error(), "not self-owned")) {
				t.Fatalf("unit %q must be rejected by the owner-binding guard, got %v", test.unit, err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("canonical unit %q must be accepted, got %v", test.unit, err)
			}
		})
	}
}

func TestServiceInstallRejectsForeignUnitBeforeSideEffects(t *testing.T) {
	for _, unit := range []string{
		"foreign-baseharbor-node-connector.podman.container",
		"baseharbor-node-connector.podman.container.evil",
		"foreign-baseharbor-node-connector.evil.container",
		"baseharbor-node-connector.docker.container/baseharbor-node-connector.podman.container",
	} {
		t.Run(unit, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			configHome := t.TempDir()
			callLog := filepath.Join(t.TempDir(), "systemctl-calls")
			stubDir := writeSystemctlStub(t, `#!/bin/sh
printf '%s\n' "$*" >> "$SYSTEMCTL_CALL_LOG"
case "$*" in
  "--user show-environment") exit 0 ;;
  "--user is-active "*) echo active; exit 0 ;;
  *) exit 0 ;;
esac
`)
			t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("SYSTEMCTL_CALL_LOG", callLog)
			t.Setenv("XDG_CONFIG_HOME", configHome)

			var stderr bytes.Buffer
			err := serviceRun(context.Background(), []string{"--unit", unit, "--state-root", root, "--op", "install"}, &stderr)
			if err == nil || !strings.Contains(err.Error(), "unit identity is not self-owned") {
				t.Fatalf("foreign unit must be rejected before install, got %v", err)
			}
			if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
				t.Fatalf("rejected unit created state path %q: %v", root, statErr)
			}
			if _, statErr := os.Stat(filepath.Join(configHome, "systemd", "user")); !os.IsNotExist(statErr) {
				t.Fatalf("rejected unit created unit directory: %v", statErr)
			}
			if _, statErr := os.Stat(callLog); !os.IsNotExist(statErr) {
				t.Fatalf("rejected unit invoked systemctl; log=%q err=%v", callLog, statErr)
			}
		})
	}
}

func TestServiceInstallReturnsTypedErrorWhenEnableFails(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	configHome := t.TempDir()
	callLog := filepath.Join(t.TempDir(), "systemctl-calls")
	stubDir := writeSystemctlStub(t, `#!/bin/sh
printf '%s\n' "$*" >> "$SYSTEMCTL_CALL_LOG"
case "$*" in
  "--user show-environment"|"--user daemon-reload") exit 0 ;;
  "--user start "*|"--user is-active "*) echo active; exit 0 ;;
  "--user enable "*) echo "injected enable failure" >&2; exit 42 ;;
  "--user is-enabled "*) echo disabled; exit 1 ;;
  *) exit 0 ;;
esac
`)
	t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SYSTEMCTL_CALL_LOG", callLog)
	t.Setenv("XDG_CONFIG_HOME", configHome)

	unit := "baseharbor-node-connector.podman.container"
	var stderr bytes.Buffer
	err := serviceRun(context.Background(), []string{"--unit", unit, "--state-root", root, "--op", "install"}, &stderr)
	if err == nil {
		t.Fatal("install must fail when enabling the unit fails")
	}
	if got := fmt.Sprintf("%T", err); got != "*main.ServiceSetupError" {
		t.Fatalf("enable failure must return typed setup error, got %s: %v", got, err)
	}
	if !strings.Contains(err.Error(), unit) || !strings.Contains(err.Error(), "remains installed") || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("setup error must identify the partial installed state, got %v", err)
	}
	if strings.Contains(strings.ToLower(stderr.String()+err.Error()), "success") {
		t.Fatalf("failed setup emitted success protocol text: stderr=%q error=%q", stderr.String(), err)
	}

	unitFile := filepath.Join(configHome, "systemd", "user", "baseharbor-node-connector.podman.service")
	if _, statErr := os.Stat(unitFile); statErr != nil {
		t.Fatalf("partial unit file must remain explicitly identified by the setup error: %v", statErr)
	}
	output, checkErr := exec.Command("systemctl", "--user", "is-enabled", "baseharbor-node-connector.podman.service").CombinedOutput()
	if checkErr == nil {
		t.Fatalf("injected failure unexpectedly enabled the unit: %s", output)
	}
	exitErr, ok := checkErr.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 || strings.TrimSpace(string(output)) != "disabled" {
		t.Fatalf("is-enabled after injected failure = %q, %v; want disabled / exit 1", output, checkErr)
	}
	callBytes, err := os.ReadFile(callLog)
	if err != nil || !strings.Contains(string(callBytes), "--user enable baseharbor-node-connector.podman.service") {
		t.Fatalf("install did not reach injected enable operation: log=%q err=%v", callBytes, err)
	}
}

func writeSystemctlStub(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
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
