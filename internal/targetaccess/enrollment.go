package targetaccess

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const EnrollmentContractVersion = "baseharbor.target-access-enrollment/v1"

type EnrollmentRequest struct {
	ContractVersion string `json:"contract_version"`
	NodeID          string `json:"node_id"`
	TargetID        string `json:"target_id"`
	Runtime         string `json:"runtime"`
	CSRPEM          string `json:"csr_pem"`
	Nonce           string `json:"nonce"`
}

func (r EnrollmentRequest) Validate() error {
	if r.ContractVersion != EnrollmentContractVersion {
		return fmt.Errorf("unsupported enrollment contract version %q", r.ContractVersion)
	}
	for name, value := range map[string]string{
		"node_id": r.NodeID,
		"target_id": r.TargetID,
		"runtime": r.Runtime,
		"csr_pem": r.CSRPEM,
		"nonce": r.Nonce,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	block, _ := pem.Decode([]byte(r.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return errors.New("csr_pem must contain one PKCS#10 certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("verify certificate request signature: %w", err)
	}
	return nil
}

type EnrollmentResponse struct {
	ContractVersion string       `json:"contract_version"`
	Node             NodeIdentity `json:"node"`
	CertificatePEM   string       `json:"certificate_pem"`
	TrustBundlePEM   string       `json:"trust_bundle_pem"`
	Nonce            string       `json:"nonce,omitempty"`
	NotAfter         time.Time    `json:"not_after"`
}

func (r EnrollmentResponse) Validate(now time.Time) error {
	if r.ContractVersion != EnrollmentContractVersion {
		return fmt.Errorf("unsupported enrollment contract version %q", r.ContractVersion)
	}
	if err := r.Node.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.CertificatePEM) == "" {
		return errors.New("certificate_pem is required")
	}
	if strings.TrimSpace(r.TrustBundlePEM) == "" {
		return errors.New("trust_bundle_pem is required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if r.NotAfter.IsZero() || !r.NotAfter.After(now) {
		return errors.New("enrollment certificate is expired")
	}
	return nil
}
