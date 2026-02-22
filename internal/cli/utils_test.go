package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remiblancher/qpki/internal/crypto"
)

// =============================================================================
// FirstOrEmpty Tests
// =============================================================================

func TestU_FirstOrEmpty(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "[Unit] FirstOrEmpty: empty slice",
			input:    []string{},
			expected: "",
		},
		{
			name:     "[Unit] FirstOrEmpty: nil slice",
			input:    nil,
			expected: "",
		},
		{
			name:     "[Unit] FirstOrEmpty: single element",
			input:    []string{"first"},
			expected: "first",
		},
		{
			name:     "[Unit] FirstOrEmpty: multiple elements",
			input:    []string{"first", "second", "third"},
			expected: "first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FirstOrEmpty(tt.input)
			if result != tt.expected {
				t.Errorf("FirstOrEmpty() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Certificate Helper Tests
// =============================================================================

// generateTestCert creates a test certificate for testing purposes.
func generateTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
			Country:      []string{"FR"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func TestU_LoadCertFromPath(t *testing.T) {
	t.Run("[Unit] LoadCertFromPath: valid PEM certificate", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")

		cert := generateTestCert(t)

		// Write certificate to file
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatalf("failed to write cert file: %v", err)
		}

		loaded, err := LoadCertFromPath(certPath)
		if err != nil {
			t.Fatalf("LoadCertFromPath() error = %v", err)
		}

		if loaded.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("LoadCertFromPath() CN = %s, want %s", loaded.Subject.CommonName, cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] LoadCertFromPath: file not found", func(t *testing.T) {
		_, err := LoadCertFromPath("/nonexistent/path/cert.pem")
		if err == nil {
			t.Error("LoadCertFromPath() should fail for non-existent file")
		}
	})

	t.Run("[Unit] LoadCertFromPath: invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(certPath, []byte("not a valid PEM"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadCertFromPath(certPath)
		if err == nil {
			t.Error("LoadCertFromPath() should fail for invalid PEM")
		}
	})

	t.Run("[Unit] LoadCertFromPath: invalid certificate data", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid_cert.pem")

		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid certificate data"),
		})
		if err := os.WriteFile(certPath, invalidPEM, 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadCertFromPath(certPath)
		if err == nil {
			t.Error("LoadCertFromPath() should fail for invalid certificate data")
		}
	})
}

func TestU_SaveCertToPath(t *testing.T) {
	t.Run("[Unit] SaveCertToPath: success", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "saved_cert.pem")

		cert := generateTestCert(t)

		if err := SaveCertToPath(certPath, cert); err != nil {
			t.Fatalf("SaveCertToPath() error = %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			t.Error("SaveCertToPath() did not create file")
		}

		// Verify certificate can be loaded back
		loaded, err := LoadCertFromPath(certPath)
		if err != nil {
			t.Fatalf("failed to load saved cert: %v", err)
		}

		if loaded.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("Loaded CN = %s, want %s", loaded.Subject.CommonName, cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] SaveCertToPath: invalid path", func(t *testing.T) {
		cert := generateTestCert(t)
		err := SaveCertToPath("/nonexistent/directory/cert.pem", cert)
		if err == nil {
			t.Error("SaveCertToPath() should fail for invalid path")
		}
	})
}

func TestU_WriteCertPEM(t *testing.T) {
	t.Run("[Unit] WriteCertPEM: success", func(t *testing.T) {
		cert := generateTestCert(t)
		var buf bytes.Buffer

		if err := WriteCertPEM(&buf, cert); err != nil {
			t.Fatalf("WriteCertPEM() error = %v", err)
		}

		// Verify output is valid PEM
		block, _ := pem.Decode(buf.Bytes())
		if block == nil {
			t.Fatal("WriteCertPEM() did not produce valid PEM")
		}

		if block.Type != "CERTIFICATE" {
			t.Errorf("WriteCertPEM() PEM type = %s, want CERTIFICATE", block.Type)
		}
	})
}

func TestU_ParseCertificatesPEM(t *testing.T) {
	t.Run("[Unit] ParseCertificatesPEM: single certificate", func(t *testing.T) {
		cert := generateTestCert(t)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		certs, err := ParseCertificatesPEM(certPEM)
		if err != nil {
			t.Fatalf("ParseCertificatesPEM() error = %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("ParseCertificatesPEM() returned %d certs, want 1", len(certs))
		}
	})

	t.Run("[Unit] ParseCertificatesPEM: multiple certificates", func(t *testing.T) {
		cert1 := generateTestCert(t)
		cert2 := generateTestCert(t)

		var data []byte
		data = append(data, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert1.Raw,
		})...)
		data = append(data, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert2.Raw,
		})...)

		certs, err := ParseCertificatesPEM(data)
		if err != nil {
			t.Fatalf("ParseCertificatesPEM() error = %v", err)
		}

		if len(certs) != 2 {
			t.Errorf("ParseCertificatesPEM() returned %d certs, want 2", len(certs))
		}
	})

	t.Run("[Unit] ParseCertificatesPEM: empty data", func(t *testing.T) {
		certs, err := ParseCertificatesPEM([]byte{})
		if err != nil {
			t.Fatalf("ParseCertificatesPEM() error = %v", err)
		}

		if len(certs) != 0 {
			t.Errorf("ParseCertificatesPEM() returned %d certs, want 0", len(certs))
		}
	})

	t.Run("[Unit] ParseCertificatesPEM: invalid PEM", func(t *testing.T) {
		certs, err := ParseCertificatesPEM([]byte("not valid pem"))
		if err != nil {
			t.Fatalf("ParseCertificatesPEM() error = %v", err)
		}

		if len(certs) != 0 {
			t.Errorf("ParseCertificatesPEM() returned %d certs, want 0", len(certs))
		}
	})

	t.Run("[Unit] ParseCertificatesPEM: skips non-certificate blocks", func(t *testing.T) {
		cert := generateTestCert(t)

		var data []byte
		// Add a private key block (should be skipped)
		data = append(data, pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: []byte("fake key"),
		})...)
		// Add the certificate
		data = append(data, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)

		certs, err := ParseCertificatesPEM(data)
		if err != nil {
			t.Fatalf("ParseCertificatesPEM() error = %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("ParseCertificatesPEM() returned %d certs, want 1", len(certs))
		}
	})

	t.Run("[Unit] ParseCertificatesPEM: invalid certificate data", func(t *testing.T) {
		invalidPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte("invalid certificate data"),
		})

		_, err := ParseCertificatesPEM(invalidPEM)
		if err == nil {
			t.Error("ParseCertificatesPEM() should fail for invalid certificate data")
		}
	})
}

// =============================================================================
// CopyFile Tests
// =============================================================================

func TestU_CopyFile(t *testing.T) {
	t.Run("[Unit] CopyFile: success", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcPath := filepath.Join(tmpDir, "source.txt")
		dstPath := filepath.Join(tmpDir, "dest.txt")

		content := []byte("test content")
		if err := os.WriteFile(srcPath, content, 0644); err != nil {
			t.Fatalf("failed to create source file: %v", err)
		}

		if err := CopyFile(srcPath, dstPath); err != nil {
			t.Fatalf("CopyFile() error = %v", err)
		}

		// Verify destination file content
		dstContent, err := os.ReadFile(dstPath)
		if err != nil {
			t.Fatalf("failed to read destination file: %v", err)
		}

		if !bytes.Equal(dstContent, content) {
			t.Errorf("CopyFile() content = %q, want %q", dstContent, content)
		}
	})

	t.Run("[Unit] CopyFile: source not found", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := CopyFile("/nonexistent/source.txt", filepath.Join(tmpDir, "dest.txt"))
		if err == nil {
			t.Error("CopyFile() should fail for non-existent source")
		}
	})

	t.Run("[Unit] CopyFile: invalid destination path", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcPath := filepath.Join(tmpDir, "source.txt")

		if err := os.WriteFile(srcPath, []byte("test"), 0644); err != nil {
			t.Fatalf("failed to create source file: %v", err)
		}

		err := CopyFile(srcPath, "/nonexistent/directory/dest.txt")
		if err == nil {
			t.Error("CopyFile() should fail for invalid destination path")
		}
	})
}

// =============================================================================
// IsCompatibleAlgorithm Tests
// =============================================================================

func TestU_IsCompatibleAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		profile  crypto.AlgorithmID
		hsm      crypto.AlgorithmID
		expected bool
	}{
		{
			name:     "[Unit] IsCompatibleAlgorithm: same algorithm",
			profile:  crypto.AlgECDSAP256,
			hsm:      crypto.AlgECDSAP256,
			expected: true,
		},
		{
			name:     "[Unit] IsCompatibleAlgorithm: different algorithms",
			profile:  crypto.AlgECDSAP256,
			hsm:      crypto.AlgRSA2048,
			expected: false,
		},
		{
			name:     "[Unit] IsCompatibleAlgorithm: empty algorithms",
			profile:  "",
			hsm:      "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsCompatibleAlgorithm(tt.profile, tt.hsm)
			if result != tt.expected {
				t.Errorf("IsCompatibleAlgorithm() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// LoadCertPool Tests
// =============================================================================

func TestU_LoadCertPool(t *testing.T) {
	t.Run("[Unit] LoadCertPool: valid certificate", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "ca.pem")

		cert := generateTestCert(t)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatalf("failed to write cert file: %v", err)
		}

		pool, err := LoadCertPool(certPath)
		if err != nil {
			t.Fatalf("LoadCertPool() error = %v", err)
		}

		if pool == nil {
			t.Error("LoadCertPool() returned nil pool")
		}
	})

	t.Run("[Unit] LoadCertPool: file not found", func(t *testing.T) {
		_, err := LoadCertPool("/nonexistent/ca.pem")
		if err == nil {
			t.Error("LoadCertPool() should fail for non-existent file")
		}
	})

	t.Run("[Unit] LoadCertPool: invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(certPath, []byte("not valid pem"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadCertPool(certPath)
		if err == nil {
			t.Error("LoadCertPool() should fail for invalid PEM")
		}
	})
}
