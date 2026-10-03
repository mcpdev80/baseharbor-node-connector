package targetaccess

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	EnrollmentURL           string
	TrustBundleFile         string
	TokenFile               string
	ExpectedServerIdentity  string
	ServerName              string
	Timeout                 time.Duration
	RetainBootstrapToken    bool
}

func (c BootstrapConfig) Validate() error {
	u, err := url.Parse(strings.TrimSpace(c.EnrollmentURL))
	if err != nil || u.Scheme != "https" || strings.TrimSpace(u.Host) == "" {
		return errors.New("enrollment_url must be an absolute HTTPS URL")
	}
	for name, value := range map[string]string{
		"trust_bundle_file": c.TrustBundleFile,
		"token_file": c.TokenFile,
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

	token, err := readBootstrapToken(cfg.TokenFile)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	if err := EnsureEnrollmentPrivateKey(files.PrivateKeyFile); err != nil {
		return EnrollmentResponse{}, err
	}
	csrPEM, err := createEnrollmentCSR(files.PrivateKeyFile, node.Identity)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	nonce, err := bootstrapNonce()
	if err != nil {
		return EnrollmentResponse{}, err
	}
	enrollmentRequest := EnrollmentRequest{
		ContractVersion: EnrollmentContractVersion,
		NodeID: node.NodeID,
		TargetID: node.TargetID,
		Runtime: node.Runtime,
		CSRPEM: csrPEM,
		Nonce: nonce,
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
	req.Header.Set("Authorization", "Bearer "+token)

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

	var enrollment EnrollmentResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&enrollment); err != nil {
		return EnrollmentResponse{}, fmt.Errorf("decode bootstrap enrollment response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return EnrollmentResponse{}, errors.New("bootstrap enrollment response contains trailing JSON values")
		}
		return EnrollmentResponse{}, fmt.Errorf("decode trailing bootstrap enrollment response: %w", err)
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
	if !cfg.RetainBootstrapToken {
		if err := os.Remove(cfg.TokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
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
		RootCAs: roots,
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
			TLSClientConfig: tlsConfig,
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func readBootstrapToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("inspect bootstrap token: %w", err)
	}
	if info.IsDir() {
		return "", errors.New("bootstrap token path is a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("bootstrap token file permissions must not grant group or other access")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read bootstrap token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("bootstrap token is empty")
	}
	if strings.ContainsAny(token, "\r\n\x00") {
		return "", errors.New("bootstrap token must be a single line")
	}
	return token, nil
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

func bootstrapNonce() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validateEnrollmentBinding(expected, actual NodeIdentity) error {
	if expected.NodeID != actual.NodeID ||
		expected.TargetID != actual.TargetID ||
		expected.Runtime != actual.Runtime ||
		expected.Identity != actual.Identity {
		return errors.New("enrollment response node identity does not match bootstrap request")
	}
	return nil
}
