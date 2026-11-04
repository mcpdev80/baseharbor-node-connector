package nodeservice

import (
	"context"
	"fmt"
	"time"

	"github.com/mcpdev80/baseharbor-node-connector/internal/targetaccess"
)

// BootstrapReenrollDriver performs deterministic re-enrollment by reusing the
// security-critical enrollment primitives in internal/targetaccess. It never
// copies those checks: the nonce, one-time token, pinned server identity,
// client-only leaf binding and protected local key generation are all enforced
// by the reused functions.
type BootstrapReenrollDriver struct {
	// files is the connector's protected TLSFiles destination scope.
	files targetaccess.TLSFiles
	// bootstrap carries the enrollment endpoint, pinned CA and authorization
	// file. RetainBootstrapAuthorization must stay false so the one-time token
	// is consumed after each successful enrollment.
	bootstrap targetaccess.BootstrapConfig
	// revokedSerials returns true when a serial is currently revoked. It is the
	// only node-side policy seam; the cryptographic binding is delegated to the
	// reused install path.
	revokedSerials func(serial string) bool
	now            func() time.Time
}

// NewBootstrapReenrollDriver constructs the driver bound to a protected file
// scope and bootstrap configuration. It fails closed when the enrollment URL or
// required paths are missing.
func NewBootstrapReenrollDriver(files targetaccess.TLSFiles, bootstrap targetaccess.BootstrapConfig, revoked func(string) bool) (*BootstrapReenrollDriver, error) {
	if err := bootstrap.Validate(); err != nil {
		return nil, fmt.Errorf("invalid bootstrap enrollment config: %w", err)
	}
	return &BootstrapReenrollDriver{
		files:          files,
		bootstrap:      bootstrap,
		revokedSerials: revoked,
		now:            func() time.Time { return time.Now().UTC() },
	}, nil
}

// Reenroll performs a fresh enrollment for the identity and binds the response
// to the same node identity and protected key. A revoked serial is rejected
// before the identity files are touched. The returned serial is the enrolled
// leaf certificate serial as a lowercase hex string.
func (d *BootstrapReenrollDriver) Reenroll(ctx context.Context, identity NodeRef) (EnrollmentResult, error) {
	node := targetaccess.NodeIdentity{
		TenantID: identity.TenantID,
		NodeID:   identity.NodeID,
		TargetID: identity.TargetID,
		Runtime:  identity.Runtime,
		Identity: identity.Identity,
	}
	result, err := d.bootstrapEnroll(ctx, node)
	if err != nil {
		return EnrollmentResult{}, err
	}
	serial, err := enrollmentSerial(result.CertificatePEM)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("derive re-enrollment serial: %w", err)
	}
	if d.revokedSerials != nil && d.revokedSerials(serial) {
		return EnrollmentResult{}, ErrRevoked
	}
	if err := targetaccess.InstallEnrollment(d.files, result, d.now()); err != nil {
		return EnrollmentResult{}, fmt.Errorf("bind re-enrollment to identity files: %w", err)
	}
	return EnrollmentResult{
		Serial:    serial,
		ExpiresAt: result.NotAfter,
	}, nil
}

// bootstrapEnroll delegates to the reused, security-critical bootstrap path.
func (d *BootstrapReenrollDriver) bootstrapEnroll(ctx context.Context, node targetaccess.NodeIdentity) (targetaccess.EnrollmentResponse, error) {
	return targetaccess.BootstrapEnroll(ctx, d.bootstrap, d.files, node)
}
