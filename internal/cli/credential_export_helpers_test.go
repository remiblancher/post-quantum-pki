package cli

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// ValidateExportFlags Tests
// =============================================================================

func TestU_ValidateExportFlags(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		bundle  string
		wantErr bool
	}{
		{
			name:    "[Unit] ValidateExportFlags: valid pem/cert",
			format:  "pem",
			bundle:  "cert",
			wantErr: false,
		},
		{
			name:    "[Unit] ValidateExportFlags: valid pem/chain",
			format:  "pem",
			bundle:  "chain",
			wantErr: false,
		},
		{
			name:    "[Unit] ValidateExportFlags: valid der/cert",
			format:  "der",
			bundle:  "cert",
			wantErr: false,
		},
		{
			name:    "[Unit] ValidateExportFlags: valid pem/all",
			format:  "pem",
			bundle:  "all",
			wantErr: false,
		},
		{
			name:    "[Unit] ValidateExportFlags: invalid format",
			format:  "invalid",
			bundle:  "cert",
			wantErr: true,
		},
		{
			name:    "[Unit] ValidateExportFlags: invalid bundle",
			format:  "pem",
			bundle:  "invalid",
			wantErr: true,
		},
		{
			name:    "[Unit] ValidateExportFlags: empty format",
			format:  "",
			bundle:  "cert",
			wantErr: true,
		},
		{
			name:    "[Unit] ValidateExportFlags: empty bundle",
			format:  "pem",
			bundle:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateExportFlags(tt.format, tt.bundle)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateExportFlags() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// EncodeExportCerts Tests
// =============================================================================

func TestU_EncodeExportCerts(t *testing.T) {
	cert := generateTestCert(t)

	t.Run("[Unit] EncodeExportCerts: PEM format", func(t *testing.T) {
		data, err := EncodeExportCerts([]*x509.Certificate{cert}, "pem")
		if err != nil {
			t.Fatalf("EncodeExportCerts() error = %v", err)
		}

		if len(data) == 0 {
			t.Error("EncodeExportCerts() returned empty data")
		}
	})

	t.Run("[Unit] EncodeExportCerts: DER format single cert", func(t *testing.T) {
		data, err := EncodeExportCerts([]*x509.Certificate{cert}, "der")
		if err != nil {
			t.Fatalf("EncodeExportCerts() error = %v", err)
		}

		if len(data) != len(cert.Raw) {
			t.Errorf("EncodeExportCerts() length = %d, want %d", len(data), len(cert.Raw))
		}
	})

	t.Run("[Unit] EncodeExportCerts: DER format multiple certs", func(t *testing.T) {
		cert2 := generateTestCert(t)
		_, err := EncodeExportCerts([]*x509.Certificate{cert, cert2}, "der")
		if err == nil {
			t.Error("EncodeExportCerts() should fail for multiple certs in DER format")
		}
	})

	t.Run("[Unit] EncodeExportCerts: empty certs DER", func(t *testing.T) {
		data, err := EncodeExportCerts([]*x509.Certificate{}, "der")
		if err != nil {
			t.Fatalf("EncodeExportCerts() error = %v", err)
		}

		if data != nil {
			t.Error("EncodeExportCerts() should return nil for empty certs")
		}
	})
}

// =============================================================================
// WriteCredExportOutput Tests
// =============================================================================

func TestU_WriteCredExportOutput(t *testing.T) {
	t.Run("[Unit] WriteCredExportOutput: write to file", func(t *testing.T) {
		tmpDir := t.TempDir()
		outPath := filepath.Join(tmpDir, "output.pem")

		data := []byte("test certificate data")
		err := WriteCredExportOutput(data, outPath, "pem")
		if err != nil {
			t.Fatalf("WriteCredExportOutput() error = %v", err)
		}

		// Verify file was created
		written, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		if string(written) != string(data) {
			t.Errorf("WriteCredExportOutput() wrote %q, want %q", written, data)
		}
	})

	t.Run("[Unit] WriteCredExportOutput: DER without output file", func(t *testing.T) {
		data := []byte{0x30, 0x82, 0x01, 0x22} // DER data
		err := WriteCredExportOutput(data, "", "der")
		if err == nil {
			t.Error("WriteCredExportOutput() should fail for DER without output file")
		}
	})

	t.Run("[Unit] WriteCredExportOutput: invalid path", func(t *testing.T) {
		data := []byte("test data")
		err := WriteCredExportOutput(data, "/nonexistent/directory/output.pem", "pem")
		if err == nil {
			t.Error("WriteCredExportOutput() should fail for invalid path")
		}
	})
}
