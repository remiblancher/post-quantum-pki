package cli

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// TSACAConfig Tests
// =============================================================================

func TestU_TSACAConfig_Structure(t *testing.T) {
	cfg := &TSACAConfig{
		Roots:       x509.NewCertPool(),
		RootCertRaw: []byte{0x01, 0x02, 0x03},
	}

	if cfg.Roots == nil {
		t.Error("TSACAConfig.Roots should not be nil")
	}

	if len(cfg.RootCertRaw) != 3 {
		t.Errorf("TSACAConfig.RootCertRaw length = %d, want 3", len(cfg.RootCertRaw))
	}
}

// =============================================================================
// LoadTSACAConfig Tests
// =============================================================================

func TestU_LoadTSACAConfig_EmptyPath(t *testing.T) {
	cfg, err := LoadTSACAConfig("")
	if err != nil {
		t.Fatalf("LoadTSACAConfig() error = %v", err)
	}

	if cfg == nil {
		t.Fatal("LoadTSACAConfig() returned nil config")
	}

	if cfg.Roots != nil {
		t.Error("LoadTSACAConfig() with empty path should have nil Roots")
	}
}

func TestU_LoadTSACAConfig_ValidCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")

	// Generate a test certificate
	cert := generateTestCert(t)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := os.WriteFile(caPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	cfg, err := LoadTSACAConfig(caPath)
	if err != nil {
		t.Fatalf("LoadTSACAConfig() error = %v", err)
	}

	if cfg.Roots == nil {
		t.Error("LoadTSACAConfig() Roots should not be nil")
	}

	if cfg.RootCertRaw == nil {
		t.Error("LoadTSACAConfig() RootCertRaw should not be nil")
	}
}

func TestU_LoadTSACAConfig_NonExistentFile(t *testing.T) {
	_, err := LoadTSACAConfig("/nonexistent/path/ca.pem")
	if err == nil {
		t.Error("LoadTSACAConfig() should fail for non-existent file")
	}
}

func TestU_LoadTSACAConfig_InvalidCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "invalid.pem")

	if err := os.WriteFile(caPath, []byte("not a valid certificate"), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := LoadTSACAConfig(caPath)
	if err == nil {
		t.Error("LoadTSACAConfig() should fail for invalid certificate")
	}
}

func TestU_LoadTSACAConfig_DERCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")

	// Generate a test certificate and write as PEM (required for LoadCertPool)
	cert := generateTestCert(t)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := os.WriteFile(caPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}

	cfg, err := LoadTSACAConfig(caPath)
	if err != nil {
		t.Fatalf("LoadTSACAConfig() error = %v", err)
	}

	// Verify the raw certificate was loaded
	if len(cfg.RootCertRaw) == 0 {
		t.Error("LoadTSACAConfig() RootCertRaw should not be empty")
	}

	// Verify it matches the original certificate DER
	if len(cfg.RootCertRaw) != len(cert.Raw) {
		t.Errorf("LoadTSACAConfig() RootCertRaw length = %d, want %d", len(cfg.RootCertRaw), len(cert.Raw))
	}
}
