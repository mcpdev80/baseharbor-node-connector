package main

import (
	"bytes"
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
	}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "core.example" {
		t.Fatalf("server name = %q", cfg.ServerName)
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

func testTLSFiles(files []string) targetaccess.TLSFiles {
	return targetaccess.TLSFiles{
		CertificateFile: files[0],
		PrivateKeyFile:  files[1],
		TrustBundleFile: files[2],
	}
}
