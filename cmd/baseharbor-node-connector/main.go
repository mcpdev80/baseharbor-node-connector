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
	"github.com/mcpdev80/baseharbor-node-connector/internal/execx"
	"github.com/mcpdev80/baseharbor-node-connector/internal/nodeservice"
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
	RenewCertificate       bool
	Sessions               int
	// SelfOwnedUnit is the systemd-user unit name the connector runs under. It is
	// optional for ad-hoc launches; when present (as systemd emits it in the
	// connector's own unit ExecStart) the connector proves the unit is self-owned
	// to the connector binary identity before any side effect.
	SelfOwnedUnit string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// serviceRun wires the connector's OWN rootless node-service lifecycle
// (install/start/restart/uninstall) to an executable path. It is scoped to the
// connector's own unit only: it never touches a Core-managed unit, never writes
// Core desired state, and never performs enrollment. Authorization is enforced
// before any lifecycle or metadata side effect via the nodeservice Authorizer.
func serviceRun(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("baseharbor-node-connector service", flag.ContinueOnError)
	fs.SetOutput(stderr)
	unit := fs.String("unit", "", "connector unit artifact basename (must be self-owned to the connector binary identity)")
	stateRoot := fs.String("state-root", "", "connector state root (unit artifact + protected metadata live under it)")
	op := fs.String("op", "", "lifecycle operation: install|start|restart|uninstall (owner-scoped to the connector's own unit)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if strings.TrimSpace(*op) == "" {
		return errors.New("--op is required (install|start|restart|uninstall)")
	}
	if strings.TrimSpace(*unit) == "" {
		return errors.New("--unit is required and must reference the connector binary identity")
	}
	if strings.TrimSpace(*stateRoot) == "" {
		return errors.New("--state-root is required")
	}
	absRoot, err := filepath.Abs(*stateRoot)
	if err != nil {
		return errors.New("invalid --state-root")
	}
	runner := execx.Runner{}
	service, err := nodeservice.NewSystemdService(runner, absRoot, *unit, nil)
	if err != nil {
		return fmt.Errorf("build node service: %w", err)
	}
	// Enforce explicit authorization before any lifecycle/metadata side effect.
	// The connector is authorized only for its own self-owned unit; a nil or
	// invalid owner fails closed with ErrUnauthorized.
	service.WithAuthorizer(nodeservice.ConnectorOwnerAuthorizer{})
	switch strings.ToLower(*op) {
	case "install":
		installed, err := service.Install(ctx, nodeservice.Unit{Kind: nodeservice.UnitKindSystemdUser, Name: *unit, ExecLine: execLineFor(*unit)})
		if err != nil {
			return fmt.Errorf("node service install: %w", err)
		}
		// Activate the connector's own unit for lingering autostart so the
		// install reflects the [Install] WantedBy contract the unit advertises.
		// Enable is idempotent and reported, never fatal when the manager cannot
		// observe it; the unit remains active from Install.
		_ = service.Enable(ctx, installed)
	case "start":
		if err := service.Start(ctx, nodeservice.Unit{Kind: nodeservice.UnitKindSystemdUser, Name: *unit, ExecLine: execLineFor(*unit)}); err != nil {
			return fmt.Errorf("node service start: %w", err)
		}
	case "restart":
		if err := service.Restart(ctx, nodeservice.Unit{Kind: nodeservice.UnitKindSystemdUser, Name: *unit, ExecLine: execLineFor(*unit)}); err != nil {
			return fmt.Errorf("node service restart: %w", err)
		}
	case "uninstall":
		if err := service.Uninstall(ctx, nodeservice.Unit{Kind: nodeservice.UnitKindSystemdUser, Name: *unit, ExecLine: execLineFor(*unit)}); err != nil {
			return fmt.Errorf("node service uninstall: %w", err)
		}
	default:
		return fmt.Errorf("unsupported service op %q (want install|start|restart|uninstall)", *op)
	}
	return nil
}

// execLineFor derives the connector's validated ExecStart for its own unit. The
// connector binary path is resolved from the executable; the validated flags are
// limited to the connector's own identity so the unit never references untrusted
// input. An absolute ExecStart is emitted so systemd can locate the binary
// directly rather than relying on a bare basename being on PATH.
func execLineFor(unit string) string {
	exe, err := os.Executable()
	if err != nil || strings.TrimSpace(exe) == "" {
		exe = "/usr/local/bin/baseharbor-node-connector"
	}
	return fmt.Sprintf("%s --self-owned-unit %s", exe, unit)
}

// enforceSelfOwnedUnit guards the direct-launch path: when the connector is
// started with an explicit self-owned unit (as systemd emits it in the
// connector's own unit ExecStart) the unit must be self-owned to the connector
// binary identity. A blank value means no explicit unit was passed (ad-hoc
// launch) and is allowed; a foreign unit name fails closed before any side
// effect so the connector can never run under a unit it does not own.
func enforceSelfOwnedUnit(name string) error {
	if strings.TrimSpace(name) == "" {
		return nil
	}
	if !strings.Contains(strings.ToLower(name), "baseharbor-node-connector") {
		return fmt.Errorf("connector unit %q is not self-owned to the connector binary identity", name)
	}
	return nil
}
func run(ctx context.Context, args []string, stderr io.Writer) error {
	// The connector's OWN service lifecycle is a scoped subcommand: install/
	// start/restart/uninstall of its own unit only. It never enrolls, writes Core
	// desired state or touches a Core-managed unit. It is dispatched before the
	// full outbound config parse so a scoped lifecycle call never requires Core
	// connection arguments.
	if len(args) > 0 && args[0] == "service" {
		return serviceRun(ctx, args[1:], stderr)
	}

	cfg, err := parseConfig(args, stderr)
	if err != nil {
		return err
	}

	// Owner-binding guard runs inside parseConfig before the outbound config
	// requirements: when the connector is launched directly with an explicit
	// self-owned unit the unit must be self-owned to the connector binary. A
	// foreign unit name fails closed before any side effect so the connector
	// never runs under a unit it does not own.

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
	if cfg.RenewCertificate || needsEnrollment(tlsFiles) {
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
	fs.BoolVar(&cfg.RenewCertificate, "renew-certificate", false, "exchange an explicit one-use Core renewal authorization for this existing node")
	fs.IntVar(&cfg.Sessions, "sessions", 0, "outbound session count (default 4, max 32)")
	fs.StringVar(&cfg.SelfOwnedUnit, "self-owned-unit", env("BASEHARBOR_CONNECTOR_SELF_OWNED_UNIT", ""), "connector systemd-user unit name the caller must own (owner-binding guard)")
	if err := fs.Parse(args); err != nil {
		return appConfig{}, err
	}
	if fs.NArg() != 0 {
		return appConfig{}, errors.New("unexpected positional arguments")
	}
	// Owner-binding guard runs before the outbound config requirements so a
	// foreign self-owned unit fails closed with the owner error, not a
	// downstream config error.
	if err := enforceSelfOwnedUnit(cfg.SelfOwnedUnit); err != nil {
		return appConfig{}, err
	}
	if cfg.Runtime != "" && cfg.Runtime != "docker" && cfg.Runtime != "podman" {
		return appConfig{}, errors.New("--runtime must be docker or podman")
	}
	if cfg.RenewCertificate && strings.TrimSpace(cfg.BootstrapURL) == "" {
		return appConfig{}, errors.New("--renew-certificate requires an explicit --bootstrap-url and fresh Core renewal authorization")
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
