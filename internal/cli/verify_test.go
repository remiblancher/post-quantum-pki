package cli

import (
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/remiblancher/qpki/internal/ocsp"
)

// =============================================================================
// GetRevocationReasonString Tests
// =============================================================================

func TestU_GetRevocationReasonString(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected string
	}{
		{
			name:     "[Unit] GetRevocationReasonString: unspecified",
			code:     0,
			expected: "unspecified",
		},
		{
			name:     "[Unit] GetRevocationReasonString: keyCompromise",
			code:     1,
			expected: "keyCompromise",
		},
		{
			name:     "[Unit] GetRevocationReasonString: cACompromise",
			code:     2,
			expected: "cACompromise",
		},
		{
			name:     "[Unit] GetRevocationReasonString: affiliationChanged",
			code:     3,
			expected: "affiliationChanged",
		},
		{
			name:     "[Unit] GetRevocationReasonString: superseded",
			code:     4,
			expected: "superseded",
		},
		{
			name:     "[Unit] GetRevocationReasonString: cessationOfOperation",
			code:     5,
			expected: "cessationOfOperation",
		},
		{
			name:     "[Unit] GetRevocationReasonString: certificateHold",
			code:     6,
			expected: "certificateHold",
		},
		{
			name:     "[Unit] GetRevocationReasonString: removeFromCRL",
			code:     8,
			expected: "removeFromCRL",
		},
		{
			name:     "[Unit] GetRevocationReasonString: privilegeWithdrawn",
			code:     9,
			expected: "privilegeWithdrawn",
		},
		{
			name:     "[Unit] GetRevocationReasonString: aACompromise",
			code:     10,
			expected: "aACompromise",
		},
		{
			name:     "[Unit] GetRevocationReasonString: unknown code",
			code:     99,
			expected: "unknown (99)",
		},
		{
			name:     "[Unit] GetRevocationReasonString: code 7 (reserved)",
			code:     7,
			expected: "unknown (7)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRevocationReasonString(tt.code)
			if result != tt.expected {
				t.Errorf("GetRevocationReasonString(%d) = %s, want %s", tt.code, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// GetOCSPRevocationReasonString Tests
// =============================================================================

func TestU_GetOCSPRevocationReasonString(t *testing.T) {
	tests := []struct {
		name     string
		reason   ocsp.RevocationReason
		expected string
	}{
		{
			name:     "[Unit] GetOCSPRevocationReasonString: unspecified",
			reason:   0,
			expected: "unspecified",
		},
		{
			name:     "[Unit] GetOCSPRevocationReasonString: keyCompromise",
			reason:   1,
			expected: "keyCompromise",
		},
		{
			name:     "[Unit] GetOCSPRevocationReasonString: superseded",
			reason:   4,
			expected: "superseded",
		},
		{
			name:     "[Unit] GetOCSPRevocationReasonString: unknown",
			reason:   99,
			expected: "unknown (99)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetOCSPRevocationReasonString(tt.reason)
			if result != tt.expected {
				t.Errorf("GetOCSPRevocationReasonString(%d) = %s, want %s", tt.reason, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// CheckCRL Tests
// =============================================================================

func TestU_CheckCRL_NotRevoked(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	cert, _ := createIssuedCert(t, caCert, caKey, "test.example.com")

	// Create CRL without the cert's serial
	crlDER := createTestCRL(t, caCert, caKey, []*big.Int{big.NewInt(999)})

	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	revoked, _, _, err := CheckCRL(cert, caCert, crlPath)
	if err != nil {
		t.Fatalf("CheckCRL() error = %v", err)
	}
	if revoked {
		t.Error("CheckCRL() should return false for non-revoked certificate")
	}
}

func TestU_CheckCRL_Revoked(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	cert, _ := createIssuedCert(t, caCert, caKey, "revoked.example.com")

	// Create CRL containing the cert's serial
	crlDER := createTestCRL(t, caCert, caKey, []*big.Int{cert.SerialNumber})

	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	revoked, reason, _, err := CheckCRL(cert, caCert, crlPath)
	if err != nil {
		t.Fatalf("CheckCRL() error = %v", err)
	}
	if !revoked {
		t.Error("CheckCRL() should return true for revoked certificate")
	}
	if reason != "keyCompromise" {
		t.Errorf("CheckCRL() reason = %s, want keyCompromise", reason)
	}
}

func TestU_CheckCRL_InvalidFile(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	cert, _ := createIssuedCert(t, caCert, caKey, "test.example.com")

	_, _, _, err := CheckCRL(cert, caCert, "/nonexistent/path/crl.pem")
	if err == nil {
		t.Error("CheckCRL() should fail for non-existent file")
	}
}

func TestU_CheckCRL_InvalidCRL(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	cert, _ := createIssuedCert(t, caCert, caKey, "test.example.com")

	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "invalid.crl")
	if err := os.WriteFile(crlPath, []byte("not a valid CRL"), 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	_, _, _, err := CheckCRL(cert, caCert, crlPath)
	if err == nil {
		t.Error("CheckCRL() should fail for invalid CRL data")
	}
}

func TestU_CheckCRL_PEMFormat(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	cert, _ := createIssuedCert(t, caCert, caKey, "test.example.com")

	crlDER := createTestCRL(t, caCert, caKey, []*big.Int{})

	// Wrap CRL in PEM
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, crlPEM, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	revoked, _, _, err := CheckCRL(cert, caCert, crlPath)
	if err != nil {
		t.Fatalf("CheckCRL() PEM format error = %v", err)
	}
	if revoked {
		t.Error("CheckCRL() should return false for non-revoked certificate")
	}
}

func TestU_CheckCRL_DERFormat(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	cert, _ := createIssuedCert(t, caCert, caKey, "test.example.com")

	// Write raw DER format
	crlDER := createTestCRL(t, caCert, caKey, []*big.Int{})

	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	revoked, _, _, err := CheckCRL(cert, caCert, crlPath)
	if err != nil {
		t.Fatalf("CheckCRL() DER format error = %v", err)
	}
	if revoked {
		t.Error("CheckCRL() should return false for non-revoked certificate")
	}
}
