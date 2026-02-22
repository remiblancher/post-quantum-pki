package cli

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/qpki/internal/crypto"
	"github.com/remiblancher/qpki/internal/profile"
)

// =============================================================================
// ValidateHSMFlags Tests
// =============================================================================

func TestU_ValidateHSMFlags(t *testing.T) {
	tests := []struct {
		name           string
		useExistingKey bool
		keyLabel       string
		keyID          string
		wantErr        bool
	}{
		{
			name:           "[Unit] ValidateHSMFlags: new key with label",
			useExistingKey: false,
			keyLabel:       "my-key",
			keyID:          "",
			wantErr:        false,
		},
		{
			name:           "[Unit] ValidateHSMFlags: new key without label",
			useExistingKey: false,
			keyLabel:       "",
			keyID:          "",
			wantErr:        true,
		},
		{
			name:           "[Unit] ValidateHSMFlags: existing key with label",
			useExistingKey: true,
			keyLabel:       "existing-key",
			keyID:          "",
			wantErr:        false,
		},
		{
			name:           "[Unit] ValidateHSMFlags: existing key with id",
			useExistingKey: true,
			keyLabel:       "",
			keyID:          "key-id-123",
			wantErr:        false,
		},
		{
			name:           "[Unit] ValidateHSMFlags: existing key without label or id",
			useExistingKey: true,
			keyLabel:       "",
			keyID:          "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHSMFlags(tt.useExistingKey, tt.keyLabel, tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHSMFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// ValidateCAHSMInitFlags Tests
// =============================================================================

func TestU_ValidateCAHSMInitFlags(t *testing.T) {
	tests := []struct {
		name           string
		varFile        string
		vars           []string
		profiles       []string
		useExistingKey bool
		keyLabel       string
		keyID          string
		wantErr        bool
	}{
		{
			name:           "[Unit] ValidateCAHSMInitFlags: valid config",
			varFile:        "",
			vars:           nil,
			profiles:       []string{"ec/root-ca"},
			useExistingKey: false,
			keyLabel:       "ca-key",
			wantErr:        false,
		},
		{
			name:           "[Unit] ValidateCAHSMInitFlags: var and var-file conflict",
			varFile:        "vars.yaml",
			vars:           []string{"cn=Test"},
			profiles:       []string{"ec/root-ca"},
			useExistingKey: false,
			keyLabel:       "ca-key",
			wantErr:        true,
		},
		{
			name:           "[Unit] ValidateCAHSMInitFlags: multiple profiles",
			varFile:        "",
			vars:           nil,
			profiles:       []string{"ec/root-ca", "rsa/root-ca"},
			useExistingKey: false,
			keyLabel:       "ca-key",
			wantErr:        true,
		},
		{
			name:           "[Unit] ValidateCAHSMInitFlags: no profiles",
			varFile:        "",
			vars:           nil,
			profiles:       []string{},
			useExistingKey: false,
			keyLabel:       "ca-key",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCAHSMInitFlags(tt.varFile, tt.vars, tt.profiles, tt.useExistingKey, tt.keyLabel, tt.keyID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCAHSMInitFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// ValidateCAInitSoftwareFlags Tests
// =============================================================================

func TestU_ValidateCAInitSoftwareFlags(t *testing.T) {
	tests := []struct {
		name     string
		varFile  string
		vars     []string
		profiles []string
		wantErr  bool
	}{
		{
			name:     "[Unit] ValidateCAInitSoftwareFlags: valid config",
			varFile:  "",
			vars:     nil,
			profiles: []string{"ec/root-ca"},
			wantErr:  false,
		},
		{
			name:     "[Unit] ValidateCAInitSoftwareFlags: var and var-file conflict",
			varFile:  "vars.yaml",
			vars:     []string{"cn=Test"},
			profiles: []string{"ec/root-ca"},
			wantErr:  true,
		},
		{
			name:     "[Unit] ValidateCAInitSoftwareFlags: no profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{},
			wantErr:  true,
		},
		{
			name:     "[Unit] ValidateCAInitSoftwareFlags: multiple profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{"ec/root-ca", "rsa/root-ca"},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCAInitSoftwareFlags(tt.varFile, tt.vars, tt.profiles)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCAInitSoftwareFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// ValidateSubordinateCAFlags Tests
// =============================================================================

func TestU_ValidateSubordinateCAFlags(t *testing.T) {
	tests := []struct {
		name     string
		varFile  string
		vars     []string
		profiles []string
		wantErr  bool
	}{
		{
			name:     "[Unit] ValidateSubordinateCAFlags: valid config",
			varFile:  "",
			vars:     nil,
			profiles: []string{"ec/issuing-ca"},
			wantErr:  false,
		},
		{
			name:     "[Unit] ValidateSubordinateCAFlags: var and var-file conflict",
			varFile:  "vars.yaml",
			vars:     []string{"cn=Test"},
			profiles: []string{"ec/issuing-ca"},
			wantErr:  true,
		},
		{
			name:     "[Unit] ValidateSubordinateCAFlags: multiple profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{"ec/issuing-ca", "rsa/issuing-ca"},
			wantErr:  true,
		},
		{
			name:     "[Unit] ValidateSubordinateCAFlags: no profiles",
			varFile:  "",
			vars:     nil,
			profiles: []string{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSubordinateCAFlags(tt.varFile, tt.vars, tt.profiles)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSubordinateCAFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// EncodeCertificates Tests
// =============================================================================

func TestU_EncodeCertificates(t *testing.T) {
	cert := generateTestCert(t)

	t.Run("[Unit] EncodeCertificates: PEM format", func(t *testing.T) {
		data, err := EncodeCertificates([]*x509.Certificate{cert}, "pem")
		if err != nil {
			t.Fatalf("EncodeCertificates() error = %v", err)
		}

		if len(data) == 0 {
			t.Error("EncodeCertificates() returned empty data")
		}

		// Verify it's valid PEM
		if string(data[:27]) != "-----BEGIN CERTIFICATE-----" {
			t.Error("EncodeCertificates() did not return valid PEM")
		}
	})

	t.Run("[Unit] EncodeCertificates: DER format", func(t *testing.T) {
		data, err := EncodeCertificates([]*x509.Certificate{cert}, "der")
		if err != nil {
			t.Fatalf("EncodeCertificates() error = %v", err)
		}

		if len(data) == 0 {
			t.Error("EncodeCertificates() returned empty data")
		}

		// DER should equal raw certificate
		if len(data) != len(cert.Raw) {
			t.Errorf("EncodeCertificates() DER length = %d, want %d", len(data), len(cert.Raw))
		}
	})

	t.Run("[Unit] EncodeCertificates: DER with multiple certs", func(t *testing.T) {
		cert2 := generateTestCert(t)
		_, err := EncodeCertificates([]*x509.Certificate{cert, cert2}, "der")
		if err == nil {
			t.Error("EncodeCertificates() should fail for multiple certs in DER format")
		}
	})

	t.Run("[Unit] EncodeCertificates: PEM with multiple certs", func(t *testing.T) {
		cert2 := generateTestCert(t)
		data, err := EncodeCertificates([]*x509.Certificate{cert, cert2}, "pem")
		if err != nil {
			t.Fatalf("EncodeCertificates() error = %v", err)
		}

		if len(data) == 0 {
			t.Error("EncodeCertificates() returned empty data")
		}
	})
}

// =============================================================================
// WriteExportOutput Tests
// =============================================================================

func TestU_WriteExportOutput(t *testing.T) {
	t.Run("[Unit] WriteExportOutput: write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := filepath.Join(tmpDir, "output.pem")

		data := []byte("test certificate data")
		err := WriteExportOutput(data, outPath, 1)
		if err != nil {
			t.Fatalf("WriteExportOutput() error = %v", err)
		}

		// Verify file was created
		written, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		if string(written) != string(data) {
			t.Errorf("WriteExportOutput() wrote %q, want %q", written, data)
		}
	})

	t.Run("[Unit] WriteExportOutput: invalid path", func(t *testing.T) {
		data := []byte("test certificate data")
		err := WriteExportOutput(data, "/nonexistent/directory/output.pem", 1)
		if err == nil {
			t.Error("WriteExportOutput() should fail for invalid path")
		}
	})
}

// =============================================================================
// ProfileAlgorithmInfo Tests
// =============================================================================

func TestU_ProfileAlgorithmInfo_Structure(t *testing.T) {
	info := &ProfileAlgorithmInfo{
		Algorithm:     crypto.AlgECDSAP256,
		HybridAlg:     crypto.AlgMLDSA65,
		IsComposite:   false,
		IsCatalyst:    true,
		ValidityYears: 10,
		PathLen:       1,
	}

	if info.Algorithm != crypto.AlgECDSAP256 {
		t.Errorf("ProfileAlgorithmInfo.Algorithm = %s, want %s", info.Algorithm, crypto.AlgECDSAP256)
	}

	if !info.IsCatalyst {
		t.Error("ProfileAlgorithmInfo.IsCatalyst should be true")
	}

	if info.ValidityYears != 10 {
		t.Errorf("ProfileAlgorithmInfo.ValidityYears = %d, want 10", info.ValidityYears)
	}
}

// =============================================================================
// ExtractProfileAlgorithmInfo Tests
// =============================================================================

func TestU_ExtractProfileAlgorithmInfo(t *testing.T) {
	t.Run("[Unit] ExtractProfileAlgorithmInfo: basic profile", func(t *testing.T) {
		prof := &profile.Profile{
			Algorithm: "ecdsa-p256",
			Validity:  365 * 24 * time.Hour,
		}

		info, err := ExtractProfileAlgorithmInfo(prof)
		if err != nil {
			t.Fatalf("ExtractProfileAlgorithmInfo() error = %v", err)
		}

		if info.ValidityYears != 1 {
			t.Errorf("ExtractProfileAlgorithmInfo() ValidityYears = %d, want 1", info.ValidityYears)
		}
	})
}

// =============================================================================
// BuildCAConfigFromProfile Tests
// =============================================================================

func TestU_BuildCAConfigFromProfile(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
	}

	subject := pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"FR"},
	}

	algInfo := &ProfileAlgorithmInfo{
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
	}

	cfg, err := BuildCAConfigFromProfile(prof, subject, algInfo, "secret")
	if err != nil {
		t.Fatalf("BuildCAConfigFromProfile() error = %v", err)
	}

	if cfg.CommonName != "Test CA" {
		t.Errorf("BuildCAConfigFromProfile() CommonName = %s, want Test CA", cfg.CommonName)
	}

	if cfg.ValidityYears != 10 {
		t.Errorf("BuildCAConfigFromProfile() ValidityYears = %d, want 10", cfg.ValidityYears)
	}
}

func TestU_BuildCAConfigFromProfile_HybridError(t *testing.T) {
	prof := &profile.Profile{
		Algorithm: "ecdsa-p256",
		Validity:  10 * 365 * 24 * time.Hour,
	}

	subject := pkix.Name{
		CommonName: "Test CA",
	}

	// Non-PQC hybrid algorithm should fail
	algInfo := &ProfileAlgorithmInfo{
		Algorithm:     crypto.AlgECDSAP256,
		HybridAlg:     crypto.AlgECDSAP384, // Not a PQC algorithm
		ValidityYears: 10,
		PathLen:       1,
	}

	_, err := BuildCAConfigFromProfile(prof, subject, algInfo, "secret")
	if err == nil {
		t.Error("BuildCAConfigFromProfile() should fail for non-PQC hybrid algorithm")
	}
}
