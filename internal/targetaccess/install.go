package targetaccess

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func InstallEnrollment(files TLSFiles, response EnrollmentResponse, now time.Time) error {
	if err := response.Validate(now); err != nil {
		return err
	}
	cert, err := firstCertificate([]byte(response.CertificatePEM))
	if err != nil {
		return fmt.Errorf("parse enrollment certificate: %w", err)
	}
	if err := verifyPeerIdentity(cert, response.Node.Identity); err != nil {
		return fmt.Errorf("verify enrolled node identity: %w", err)
	}
	if err := certificateMatchesPrivateKey(cert, files.PrivateKeyFile); err != nil {
		return err
	}
	roots, err := parseCertPool([]byte(response.TrustBundlePEM))
	if err != nil {
		return fmt.Errorf("parse enrollment trust bundle: %w", err)
	}
	verifyTime := now
	if verifyTime.IsZero() {
		verifyTime = time.Now().UTC()
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: verifyTime,
	}); err != nil {
		return fmt.Errorf("verify enrollment certificate chain: %w", err)
	}
	if response.NotAfter.After(cert.NotAfter) {
		return errors.New("enrollment response expiry exceeds certificate validity")
	}
	if err := atomicWriteFile(files.CertificateFile, []byte(response.CertificatePEM), 0o600); err != nil {
		return fmt.Errorf("install enrollment certificate: %w", err)
	}
	if err := atomicWriteFile(files.TrustBundleFile, []byte(response.TrustBundlePEM), 0o600); err != nil {
		return fmt.Errorf("install enrollment trust bundle: %w", err)
	}
	return nil
}

func certificateMatchesPrivateKey(cert *x509.Certificate, privateKeyPath string) error {
	data, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("private key file contains no PEM block")
	}
	key, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("private key is not a crypto signer")
	}
	certPublic, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(certPublic, keyPublic) {
		return errors.New("enrollment certificate does not match local private key")
	}
	return nil
}

func parsePrivateKey(data []byte) (any, error) {
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key encoding")
}

func firstCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate PEM contains no certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCertPool(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := data
	count := 0
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
		count++
	}
	if count == 0 {
		return nil, errors.New("trust bundle contains no certificates")
	}
	return pool, nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	path = filepath.Clean(path)
	if path == "." || path == "" {
		return errors.New("destination path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	resolvedDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return err
	}
	if resolvedDir != absDir {
		return errors.New("identity directory must not contain symlinks")
	}
	tmp, err := os.CreateTemp(absDir, ".baseharbor-identity-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
