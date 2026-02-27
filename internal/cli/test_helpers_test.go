package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// =============================================================================
// Shared Test Helpers
// =============================================================================

// generateTestCAAndKey creates a self-signed CA certificate and its private key.
func generateTestCAAndKey(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
			Organization: []string{"Test Org"},
			Country:      []string{"FR"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	return cert, key
}

// createIssuedCert creates a certificate signed by the given CA.
func createIssuedCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate end-entity key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create end-entity certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse end-entity certificate: %v", err)
	}

	return cert, key
}

// generateTestCSR creates a test CSR PEM-encoded with ECDSA P-256.
func generateTestCSR(t *testing.T, cn string, dnsNames []string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CSR key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		DNSNames: dnsNames,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, key
}

// createTestCRL creates a signed CRL containing the given revoked serial numbers.
func createTestCRL(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, revokedSerials []*big.Int) []byte {
	t.Helper()

	revokedEntries := make([]x509.RevocationListEntry, len(revokedSerials))
	for i, serial := range revokedSerials {
		revokedEntries[i] = x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-1 * time.Hour),
			ReasonCode:     1, // keyCompromise
		}
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: revokedEntries,
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-1 * time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, caKey)
	if err != nil {
		t.Fatalf("failed to create CRL: %v", err)
	}

	return crlDER
}

// saveKeyPEM saves an EC private key in PEM format.
func saveKeyPEM(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
}

// saveCertPEM saves a certificate in PEM format.
func saveCertPEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err := os.WriteFile(path, certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
}

// mockCmd implements the Changed(string) bool interface for testing ApplyValidityOverrides.
type mockCmd struct {
	changedFields map[string]bool
}

func (m *mockCmd) Changed(flag string) bool {
	return m.changedFields[flag]
}
