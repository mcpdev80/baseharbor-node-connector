package targetaccess

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxEnrollmentResponseBytes = 1 << 20

type BootstrapConfig struct {
	EnrollmentURL          string
	TrustBundleFile        string
	AuthorizationFile              string
	ExpectedServerIdentity string
	ServerName             string
	Timeout                time.Duration
	RetainBootstrapAuthorization   bool
}

func (c BootstrapConfig) Validate() error {
	u, err := url.Parse(strings.TrimSpace(c.EnrollmentURL))
	if err != nil || u.Scheme != "https" || strings.TrimSpace(u.Host) == "" {
		return errors.New("enrollment_url must be an absolute HTTPS URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return errors.New("enrollment_url must not contain credentials, query parameters or fragments")
	}
	for name, value := range map[string]string{
		"trust_bundle_file":        c.TrustBundleFile,
		"authorization_file":               c.AuthorizationFile,
		"expected_server_identity": c.ExpectedServerIdentity,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if c.Timeout < 0 {
		return errors.New("bootstrap timeout must not be negative")
	}
	return nil
}

func BootstrapEnroll(ctx context.Context, cfg BootstrapConfig, files TLSFiles, node NodeIdentity) (EnrollmentResponse, error) {
	if err := cfg.Validate(); err != nil {
		return EnrollmentResponse{}, err
	}
	if err := node.Validate(); err != nil {
		return EnrollmentResponse{}, err
	}
	if strings.TrimSpace(files.PrivateKeyFile) == "" ||
		strings.TrimSpace(files.CertificateFile) == "" ||
		strings.TrimSpace(files.TrustBundleFile) == "" {
		return EnrollmentResponse{}, errors.New("certificate, private key and trust bundle destination paths are required")
	}

	authorization, err := readBootstrapAuthorization(cfg.AuthorizationFile, time.Now().UTC())
	if err != nil {
		return EnrollmentResponse{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, authorization.ExpiresAt)
	defer cancel()
	if err := EnsureEnrollmentPrivateKey(files.PrivateKeyFile); err != nil {
		return EnrollmentResponse{}, err
	}
	csrPEM, err := createEnrollmentCSR(files.PrivateKeyFile, node.Identity)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	nonce := authorization.Nonce
	enrollmentRequest := EnrollmentRequest{
		ContractVersion: EnrollmentContractVersion,
		TenantID:        node.TenantID,
		NodeID:          node.NodeID,
		TargetID:        node.TargetID,
		Runtime:         node.Runtime,
		CSRPEM:          csrPEM,
		Nonce:           nonce,
	}
	if err := enrollmentRequest.Validate(); err != nil {
		return EnrollmentResponse{}, err
	}
	payload, err := json.Marshal(enrollmentRequest)
	if err != nil {
		return EnrollmentResponse{}, err
	}

	client, err := bootstrapHTTPClient(cfg)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EnrollmentURL, bytes.NewReader(payload))
	if err != nil {
		return EnrollmentResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+authorization.Token)

	resp, err := client.Do(req)
	if err != nil {
		return EnrollmentResponse{}, fmt.Errorf("bootstrap enrollment request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxEnrollmentResponseBytes+1))
	if err != nil {
		return EnrollmentResponse{}, err
	}
	if len(body) > maxEnrollmentResponseBytes {
		return EnrollmentResponse{}, errors.New("bootstrap enrollment response exceeds size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return EnrollmentResponse{}, fmt.Errorf("bootstrap enrollment failed with HTTP %d", resp.StatusCode)
	}

	if ValidateTargetAccessRecord("enrollment_response", body) != nil {
		return EnrollmentResponse{}, errors.New("invalid bootstrap enrollment response")
	}
	var enrollment EnrollmentResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&enrollment); err != nil {
		return EnrollmentResponse{}, errors.New("invalid bootstrap enrollment response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return EnrollmentResponse{}, errors.New("bootstrap enrollment response contains trailing JSON values")
		}
		return EnrollmentResponse{}, errors.New("invalid bootstrap enrollment response")
	}
	if err := validateEnrollmentBinding(node, enrollment.Node); err != nil {
		return EnrollmentResponse{}, err
	}
	if enrollment.Nonce == "" || enrollment.Nonce != nonce {
		return EnrollmentResponse{}, errors.New("enrollment response nonce does not match bootstrap request")
	}
	if err := InstallEnrollment(files, enrollment, time.Now().UTC()); err != nil {
		return EnrollmentResponse{}, err
	}
	if !cfg.RetainBootstrapAuthorization {
		if err := os.Remove(cfg.AuthorizationFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return EnrollmentResponse{}, fmt.Errorf("remove consumed bootstrap token: %w", err)
		}
	}
	return enrollment, nil
}

func bootstrapHTTPClient(cfg BootstrapConfig) (*http.Client, error) {
	roots, err := loadCertPool(cfg.TrustBundleFile)
	if err != nil {
		return nil, fmt.Errorf("load bootstrap trust bundle: %w", err)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: strings.TrimSpace(cfg.ServerName),
		RootCAs:    roots,
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("bootstrap server did not present a certificate")
		}
		return verifyPeerIdentity(state.PeerCertificates[0], cfg.ExpectedServerIdentity)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

type BootstrapAuthorization struct {
	Token string `json:"token"`
	Nonce string `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

func readBootstrapAuthorization(path string, now time.Time) (BootstrapAuthorization, error) {
	invalid := func() (BootstrapAuthorization, error) {
		return BootstrapAuthorization{}, errors.New("bootstrap authorization is invalid, expired or not privately stored")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return invalid()
	}
	file, err := os.Open(path)
	if err != nil { return invalid() }
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return invalid()
	}
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data)>8192 || ValidateTargetAccessRecord("bootstrap_authorization", data) != nil {
		return invalid()
	}
	var authorization BootstrapAuthorization
	if json.Unmarshal(data, &authorization) != nil || !authorization.ExpiresAt.After(now) || authorization.ExpiresAt.After(now.Add(10*time.Minute+30*time.Second)) {
		return invalid()
	}
	return authorization, nil
}

func EnsureEnrollmentPrivateKey(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("enrollment private key path is required")
	}
	if info, err := os.Stat(path); err == nil {
		if info.IsDir() {
			return errors.New("enrollment private key path is a directory")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return errors.New("enrollment private key permissions must not grant group or other access")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return errors.New("enrollment private key contains no PEM block")
		}
		key, err := parsePrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		if _, ok := key.(crypto.Signer); !ok {
			return errors.New("enrollment private key is not a crypto signer")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect enrollment private key: %w", err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate enrollment private key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("encode enrollment private key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if len(data) == 0 {
		return errors.New("encode enrollment private key PEM")
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("install enrollment private key: %w", err)
	}
	return nil
}

func createEnrollmentCSR(privateKeyPath, identity string) (string, error) {
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("read enrollment private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("enrollment private key contains no PEM block")
	}
	key, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return "", errors.New("enrollment private key is not a crypto signer")
	}
	uri, err := url.Parse(strings.TrimSpace(identity))
	if err != nil || uri.Scheme == "" {
		return "", errors.New("node identity must be an absolute URI for enrollment")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{uri}}, signer)
	if err != nil {
		return "", fmt.Errorf("create enrollment CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}


func validateEnrollmentBinding(expected, actual NodeIdentity) error {
	if expected.TenantID != actual.TenantID || expected.NodeID != actual.NodeID ||
		expected.TargetID != actual.TargetID ||
		expected.Runtime != actual.Runtime ||
		expected.Identity != actual.Identity {
		return errors.New("enrollment response node identity does not match bootstrap request")
	}
	return nil
}
