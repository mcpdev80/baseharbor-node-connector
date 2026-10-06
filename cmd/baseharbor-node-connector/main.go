package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/mcpdev80/baseharbor-node-connector/internal/connector"
	bhruntime "github.com/mcpdev80/baseharbor-node-connector/internal/runtime"
	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

const defaultCoreIdentity = "spiffe://baseharbor/platform/core/control-plane"

var tenantIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var identitySegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type appConfig struct {
	Runtime                string
	CoreAddress            string
	ServerName             string
	CoreIdentity           string
	TenantID               string
	TargetID               string
	NodeID                 string
	NodeIdentity           string
	StateRoot              string
	StagingRoot            string
	QuadletRoot            string
	CertificateFile        string
	PrivateKeyFile         string
	TrustBundleFile        string
	RevokedSerials         string
	BootstrapURL           string
	BootstrapCA            string
	BootstrapAuthorization string
	RetainToken            bool
	Sessions               int
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stderr io.Writer) error {
	cfg, err := parseConfig(args, stderr)
	if err != nil {
		return err
	}

	service, err := connector.Open(ctx, connector.Config{
		Runtime:            bhruntime.Kind(cfg.Runtime),
		StagingRoot:        cfg.StagingRoot,
		TransportStateRoot: filepath.Join(cfg.StateRoot, "transport"),
		QuadletRoot:        cfg.QuadletRoot,
	})
	if err != nil {
		return err
	}

	identity := targetaccess.NodeIdentity{
		TenantID: cfg.TenantID,
		NodeID:   cfg.NodeID,
		TargetID: cfg.TargetID,
		Runtime:  string(service.Runtime.Kind),
		Identity: cfg.NodeIdentity,
	}
	if err := identity.Validate(); err != nil {
		return err
	}

	tlsFiles := targetaccess.TLSFiles{
		CertificateFile:      cfg.CertificateFile,
		PrivateKeyFile:       cfg.PrivateKeyFile,
		TrustBundleFile:      cfg.TrustBundleFile,
		RevokedSerialsFile:   cfg.RevokedSerials,
		ExpectedPeerIdentity: cfg.CoreIdentity,
		ServerName:           cfg.ServerName,
	}
	if needsEnrollment(tlsFiles) {
		if strings.TrimSpace(cfg.BootstrapURL) == "" {
			return errors.New("connector identity material is incomplete and no --bootstrap-url was configured")
		}
		_, err := targetaccess.BootstrapEnroll(ctx, targetaccess.BootstrapConfig{
			EnrollmentURL:                cfg.BootstrapURL,
			TrustBundleFile:              cfg.BootstrapCA,
			AuthorizationFile:            cfg.BootstrapAuthorization,
			ExpectedServerIdentity:       cfg.CoreIdentity,
			ServerName:                   cfg.ServerName,
			RetainBootstrapAuthorization: cfg.RetainToken,
		}, tlsFiles, identity)
		if err != nil {
			return fmt.Errorf("bootstrap connector identity: %w", err)
		}
	}
	if err := tlsFiles.Validate(); err != nil {
		return fmt.Errorf("connector TLS configuration: %w", err)
	}

	access, err := service.TargetAccess(identity)
	if err != nil {
		return err
	}
	defer access.Close()
	return access.RunOutboundPool(ctx, connector.OutboundPoolConfig{
		OutboundConfig: connector.OutboundConfig{
			Address: cfg.CoreAddress,
			TLS:     tlsFiles,
		},
		Sessions: cfg.Sessions,
	})
}

func parseConfig(args []string, stderr io.Writer) (appConfig, error) {
	stateRoot, err := defaultStateRoot()
	if err != nil {
		return appConfig{}, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return appConfig{}, fmt.Errorf("determine node hostname: %w", err)
	}

	cfg := appConfig{}
	fs := flag.NewFlagSet("baseharbor-node-connector", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.Runtime, "runtime", env("BASEHARBOR_CONNECTOR_RUNTIME", ""), "enrolled Docker or Podman runtime; unavailable selections never fall back")
	fs.StringVar(&cfg.CoreAddress, "core", env("BASEHARBOR_CONNECTOR_CORE", ""), "BaseHarbor Core host:port")
	fs.StringVar(&cfg.ServerName, "server-name", env("BASEHARBOR_CONNECTOR_SERVER_NAME", ""), "TLS server DNS name")
	fs.StringVar(&cfg.CoreIdentity, "core-identity", env("BASEHARBOR_CONNECTOR_CORE_IDENTITY", defaultCoreIdentity), "expected Core certificate identity")
	fs.StringVar(&cfg.TenantID, "tenant-id", env("BASEHARBOR_CONNECTOR_TENANT_ID", ""), "Core tenant UUID bound to enrollment")
	fs.StringVar(&cfg.TargetID, "target-id", env("BASEHARBOR_CONNECTOR_TARGET_ID", ""), "BaseHarbor Target ID")
	fs.StringVar(&cfg.NodeID, "node-id", env("BASEHARBOR_CONNECTOR_NODE_ID", hostname), "connector node ID")
	fs.StringVar(&cfg.NodeIdentity, "node-identity", env("BASEHARBOR_CONNECTOR_NODE_IDENTITY", ""), "connector certificate URI identity")
	fs.StringVar(&cfg.StateRoot, "state-root", env("BASEHARBOR_CONNECTOR_STATE_ROOT", stateRoot), "connector state root")
	fs.StringVar(&cfg.StagingRoot, "staging-root", env("BASEHARBOR_CONNECTOR_STAGING_ROOT", ""), "deployment staging root")
	fs.StringVar(&cfg.QuadletRoot, "quadlet-root", env("BASEHARBOR_CONNECTOR_QUADLET_ROOT", ""), "Podman Quadlet root")
	fs.StringVar(&cfg.CertificateFile, "cert", env("BASEHARBOR_CONNECTOR_CERT", ""), "connector certificate path")
	fs.StringVar(&cfg.PrivateKeyFile, "key", env("BASEHARBOR_CONNECTOR_KEY", ""), "connector private-key path")
	fs.StringVar(&cfg.TrustBundleFile, "ca", env("BASEHARBOR_CONNECTOR_CA", ""), "Core trust-bundle path")
	fs.StringVar(&cfg.RevokedSerials, "revoked-serials", env("BASEHARBOR_CONNECTOR_REVOKED_SERIALS", ""), "revoked peer serials path")
	fs.StringVar(&cfg.BootstrapURL, "bootstrap-url", env("BASEHARBOR_CONNECTOR_BOOTSTRAP_URL", ""), "HTTPS enrollment endpoint")
	fs.StringVar(&cfg.BootstrapCA, "bootstrap-ca", env("BASEHARBOR_CONNECTOR_BOOTSTRAP_CA", ""), "bootstrap CA bundle path")
	fs.StringVar(&cfg.BootstrapAuthorization, "bootstrap-authorization-file", env("BASEHARBOR_CONNECTOR_BOOTSTRAP_AUTHORIZATION_FILE", ""), "private Core-issued token/nonce/expiry JSON authorization")
	fs.BoolVar(&cfg.RetainToken, "retain-bootstrap-authorization", false, "retain consumed bootstrap authorization after successful enrollment")
	fs.IntVar(&cfg.Sessions, "sessions", 0, "outbound session count (default 4, max 32)")
	if err := fs.Parse(args); err != nil {
		return appConfig{}, err
	}
	if fs.NArg() != 0 {
		return appConfig{}, errors.New("unexpected positional arguments")
	}
	if cfg.Runtime != "" && cfg.Runtime != "docker" && cfg.Runtime != "podman" {
		return appConfig{}, errors.New("--runtime must be docker or podman")
	}

	cfg.TenantID = strings.TrimSpace(cfg.TenantID)
	cfg.CoreAddress = strings.TrimSpace(cfg.CoreAddress)
	cfg.TargetID = strings.TrimSpace(cfg.TargetID)
	cfg.NodeID = strings.TrimSpace(cfg.NodeID)
	if cfg.CoreAddress == "" {
		return appConfig{}, errors.New("--core is required")
	}
	if !tenantIDPattern.MatchString(cfg.TenantID) {
		return appConfig{}, errors.New("--tenant-id must be a canonical tenant UUID")
	}
	if cfg.TargetID == "" {
		return appConfig{}, errors.New("--target-id is required")
	}
	if !identitySegment.MatchString(cfg.TargetID) || !identitySegment.MatchString(cfg.NodeID) {
		return appConfig{}, errors.New("target-id and node-id must be bounded alphanumeric, underscore or hyphen identity segments")
	}
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(cfg.CoreAddress)
		if err != nil {
			return appConfig{}, fmt.Errorf("--core must use host:port form: %w", err)
		}
		cfg.ServerName = strings.Trim(host, "[]")
	}
	if cfg.NodeIdentity == "" {
		cfg.NodeIdentity = "spiffe://baseharbor/platform/connectors/" + cfg.TenantID + "/" + cfg.TargetID + "/" + cfg.NodeID
	}

	if cfg.NodeIdentity != "spiffe://baseharbor/platform/connectors/"+cfg.TenantID+"/"+cfg.TargetID+"/"+cfg.NodeID {
		return appConfig{}, errors.New("node identity must match the Core tenant/Target/node binding")
	}
	cfg.StateRoot, err = filepath.Abs(cfg.StateRoot)
	if err != nil {
		return appConfig{}, errors.New("invalid connector state root")
	}
	if cfg.StagingRoot == "" {
		cfg.StagingRoot = filepath.Join(cfg.StateRoot, "staging")
	}
	identityRoot := filepath.Join(cfg.StateRoot, "identity")
	if cfg.CertificateFile == "" {
		cfg.CertificateFile = filepath.Join(identityRoot, "node.crt")
	}
	if cfg.PrivateKeyFile == "" {
		cfg.PrivateKeyFile = filepath.Join(identityRoot, "node.key")
	}
	if cfg.TrustBundleFile == "" {
		cfg.TrustBundleFile = filepath.Join(identityRoot, "ca.pem")
	}
	if cfg.BootstrapCA == "" {
		cfg.BootstrapCA = filepath.Join(cfg.StateRoot, "bootstrap-ca.pem")
	}
	if cfg.BootstrapAuthorization == "" {
		cfg.BootstrapAuthorization = filepath.Join(cfg.StateRoot, "bootstrap.authorization.json")
	}
	return cfg, nil
}

func defaultStateRoot() (string, error) {
	if root := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); root != "" {
		return filepath.Join(root, "baseharbor-node-connector"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", errors.New("cannot determine connector state root")
	}
	return filepath.Join(home, ".local", "share", "baseharbor-node-connector"), nil
}

func needsEnrollment(files targetaccess.TLSFiles) bool {
	for _, path := range []string{files.CertificateFile, files.PrivateKeyFile, files.TrustBundleFile} {
		if _, err := os.Stat(path); err != nil {
			return true
		}
	}
	return false
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
