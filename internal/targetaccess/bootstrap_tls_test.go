package targetaccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Hostname and CA verification do not establish the installation identity.
func TestBootstrapTLSRequiresCoreIdentityAlongsideTrustedHostname(t *testing.T) {
	const identity = "spiffe://baseharbor/platform/core/browser-connector"
	for _, scoped := range []bool{false, true} {
		t.Run(map[bool]string{false: "DNS-only-rejected", true: "Core-identity-accepted"}[scoped], func(t *testing.T) {
			ca, caKey, caPEM := newTestCA(t)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if scoped {
				uri, err := url.Parse(identity)
				if err != nil {
					t.Fatal(err)
				}
				leaf.URIs = []*url.URL{uri}
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			server.StartTLS()
			defer server.Close()
			roots := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(roots, caPEM, 0600); err != nil {
				t.Fatal(err)
			}
			client, err := bootstrapHTTPClient(BootstrapConfig{TrustBundleFile: roots, ExpectedServerIdentity: identity, ServerName: "localhost"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			reply, err := client.Get(server.URL)
			if !scoped {
				if err == nil {
					reply.Body.Close()
					t.Fatal("DNS-only frontend authenticated as Core")
				}
				return
			}
			if err != nil {
				t.Fatal("trusted Core identity rejected", err)
			}
			defer reply.Body.Close()
			if reply.StatusCode != http.StatusNoContent {
				t.Fatal("unexpected response", reply.StatusCode)
			}
		})
	}
}
