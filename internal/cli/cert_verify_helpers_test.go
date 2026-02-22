package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// CheckValidityPeriod Tests
// =============================================================================

func TestU_CheckValidityPeriod(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name         string
		notBefore    time.Time
		notAfter     time.Time
		expectValid  bool
		expectStatus string
	}{
		{
			name:         "[Unit] CheckValidityPeriod: valid certificate",
			notBefore:    now.Add(-24 * time.Hour),
			notAfter:     now.Add(365 * 24 * time.Hour),
			expectValid:  true,
			expectStatus: "",
		},
		{
			name:         "[Unit] CheckValidityPeriod: not yet valid",
			notBefore:    now.Add(24 * time.Hour),
			notAfter:     now.Add(365 * 24 * time.Hour),
			expectValid:  false,
			expectStatus: "NOT YET VALID",
		},
		{
			name:         "[Unit] CheckValidityPeriod: expired certificate",
			notBefore:    now.Add(-365 * 24 * time.Hour),
			notAfter:     now.Add(-24 * time.Hour),
			expectValid:  false,
			expectStatus: "EXPIRED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				NotBefore: tt.notBefore,
				NotAfter:  tt.notAfter,
			}

			valid, statusMsg, _ := CheckValidityPeriod(cert)

			if valid != tt.expectValid {
				t.Errorf("CheckValidityPeriod() valid = %v, want %v", valid, tt.expectValid)
			}

			if statusMsg != tt.expectStatus {
				t.Errorf("CheckValidityPeriod() statusMsg = %s, want %s", statusMsg, tt.expectStatus)
			}
		})
	}
}

func TestU_CheckValidityPeriod_NotYetValid_Days(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(10 * 24 * time.Hour)
	notAfter := now.Add(375 * 24 * time.Hour)

	cert := &x509.Certificate{
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	valid, statusMsg, expiredInfo := CheckValidityPeriod(cert)

	if valid {
		t.Error("CheckValidityPeriod() should return false for not yet valid cert")
	}

	if statusMsg != "NOT YET VALID" {
		t.Errorf("CheckValidityPeriod() statusMsg = %s, want NOT YET VALID", statusMsg)
	}

	if expiredInfo == "" {
		t.Error("CheckValidityPeriod() should return expiredInfo for not yet valid cert")
	}
}

func TestU_CheckValidityPeriod_Expired_Days(t *testing.T) {
	now := time.Now()
	notBefore := now.Add(-375 * 24 * time.Hour)
	notAfter := now.Add(-10 * 24 * time.Hour)

	cert := &x509.Certificate{
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	valid, statusMsg, expiredInfo := CheckValidityPeriod(cert)

	if valid {
		t.Error("CheckValidityPeriod() should return false for expired cert")
	}

	if statusMsg != "EXPIRED" {
		t.Errorf("CheckValidityPeriod() statusMsg = %s, want EXPIRED", statusMsg)
	}

	if expiredInfo == "" {
		t.Error("CheckValidityPeriod() should return expiredInfo for expired cert")
	}
}

// =============================================================================
// VerifyResult Tests
// =============================================================================

func TestU_VerifyResult_Structure(t *testing.T) {
	result := &VerifyResult{
		IsValid:        true,
		StatusMsg:      "VALID",
		RevocationInfo: "Not checked",
		ExpiredInfo:    "",
	}

	if !result.IsValid {
		t.Error("VerifyResult.IsValid should be true")
	}

	if result.StatusMsg != "VALID" {
		t.Errorf("VerifyResult.StatusMsg = %s, want VALID", result.StatusMsg)
	}
}

// =============================================================================
// CheckRevocationStatus Tests
// =============================================================================

func TestU_CheckRevocationStatus_NoCRLOrOCSP(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}

	revoked, info, err := CheckRevocationStatus(cert, cert, "", "")

	if err != nil {
		t.Fatalf("CheckRevocationStatus() error = %v", err)
	}

	if revoked {
		t.Error("CheckRevocationStatus() should return false when no CRL/OCSP")
	}

	if info == "" {
		t.Error("CheckRevocationStatus() should return info message")
	}

	// Suppress unused variable warning
	_ = key
}

// =============================================================================
// Integration test for verify flow
// =============================================================================

func TestU_VerifyFlow_ValidCertificate(t *testing.T) {
	// Create a self-signed certificate for testing
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Test validity period
	valid, statusMsg, _ := CheckValidityPeriod(cert)
	if !valid {
		t.Errorf("CheckValidityPeriod() = %v, %s; want true, empty", valid, statusMsg)
	}

	// Test revocation check (no CRL/OCSP)
	revoked, info, err := CheckRevocationStatus(cert, cert, "", "")
	if err != nil {
		t.Errorf("CheckRevocationStatus() error = %v", err)
	}
	if revoked {
		t.Error("CheckRevocationStatus() should return false")
	}
	if info == "" {
		t.Error("CheckRevocationStatus() should return info")
	}
}
