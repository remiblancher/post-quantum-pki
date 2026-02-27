package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// =============================================================================
// LoadSigningCert Tests
// =============================================================================

func TestU_LoadSigningCert(t *testing.T) {
	t.Run("[Unit] LoadSigningCert: valid certificate", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")

		cert := generateTestCert(t)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatalf("failed to write cert file: %v", err)
		}

		loaded, err := LoadSigningCert(certPath)
		if err != nil {
			t.Fatalf("LoadSigningCert() error = %v", err)
		}

		if loaded.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("LoadSigningCert() CN = %s, want %s", loaded.Subject.CommonName, cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] LoadSigningCert: file not found", func(t *testing.T) {
		_, err := LoadSigningCert("/nonexistent/path/cert.pem")
		if err == nil {
			t.Error("LoadSigningCert() should fail for non-existent file")
		}
	})

	t.Run("[Unit] LoadSigningCert: invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(certPath, []byte("not a valid PEM"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadSigningCert(certPath)
		if err == nil {
			t.Error("LoadSigningCert() should fail for invalid PEM")
		}
	})

	t.Run("[Unit] LoadSigningCert: wrong PEM type", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "key.pem")

		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: []byte("fake key data"),
		})
		if err := os.WriteFile(certPath, keyPEM, 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadSigningCert(certPath)
		if err == nil {
			t.Error("LoadSigningCert() should fail for non-certificate PEM")
		}
	})
}

// =============================================================================
// LoadDecryptionCert Tests
// =============================================================================

func TestU_LoadDecryptionCert(t *testing.T) {
	t.Run("[Unit] LoadDecryptionCert: valid certificate", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "cert.pem")

		cert := generateTestCert(t)
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			t.Fatalf("failed to write cert file: %v", err)
		}

		loaded, err := LoadDecryptionCert(certPath)
		if err != nil {
			t.Fatalf("LoadDecryptionCert() error = %v", err)
		}

		if loaded.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("LoadDecryptionCert() CN = %s, want %s", loaded.Subject.CommonName, cert.Subject.CommonName)
		}
	})

	t.Run("[Unit] LoadDecryptionCert: file not found", func(t *testing.T) {
		_, err := LoadDecryptionCert("/nonexistent/path/cert.pem")
		if err == nil {
			t.Error("LoadDecryptionCert() should fail for non-existent file")
		}
	})

	t.Run("[Unit] LoadDecryptionCert: invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		certPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(certPath, []byte("not a valid PEM"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadDecryptionCert(certPath)
		if err == nil {
			t.Error("LoadDecryptionCert() should fail for invalid PEM")
		}
	})
}

// =============================================================================
// LoadDecryptionKey Tests
// =============================================================================

func TestU_LoadDecryptionKey(t *testing.T) {
	t.Run("[Unit] LoadDecryptionKey: file not found", func(t *testing.T) {
		_, err := LoadDecryptionKey("/nonexistent/path/key.pem", "")
		if err == nil {
			t.Error("LoadDecryptionKey() should fail for non-existent file")
		}
	})

	t.Run("[Unit] LoadDecryptionKey: invalid PEM", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, "invalid.pem")

		if err := os.WriteFile(keyPath, []byte("not a valid PEM"), 0644); err != nil {
			t.Fatalf("failed to write file: %v", err)
		}

		_, err := LoadDecryptionKey(keyPath, "")
		if err == nil {
			t.Error("LoadDecryptionKey() should fail for invalid PEM")
		}
	})

	t.Run("[Unit] LoadDecryptionKey: valid EC key", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyPath := filepath.Join(tmpDir, "ec.key")

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		saveKeyPEM(t, keyPath, key)

		result, err := LoadDecryptionKey(keyPath, "")
		if err != nil {
			t.Fatalf("LoadDecryptionKey() error = %v", err)
		}

		if result == nil {
			t.Error("LoadDecryptionKey() should return non-nil key")
		}
	})
}

// =============================================================================
// LoadSigningKey Tests
// =============================================================================

func TestU_LoadSigningKey_NoKeyPath(t *testing.T) {
	_, err := LoadSigningKey("", "", "", "", "", nil)
	if err == nil {
		t.Error("LoadSigningKey() should fail when no key path and no HSM config")
	}
}

func TestU_LoadSigningKey_ValidSoftwareKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "signing.key")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	saveKeyPEM(t, keyPath, key)

	signer, err := LoadSigningKey("", keyPath, "", "", "", nil)
	if err != nil {
		t.Fatalf("LoadSigningKey() error = %v", err)
	}

	if signer == nil {
		t.Error("LoadSigningKey() should return non-nil signer")
	}
}

// =============================================================================
// LoadStandardKey Tests
// =============================================================================

func TestU_LoadStandardKey_ValidECKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "standard.key")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	saveKeyPEM(t, keyPath, key)

	result, err := LoadStandardKey(keyPath, "")
	if err != nil {
		t.Fatalf("LoadStandardKey() error = %v", err)
	}

	if result == nil {
		t.Error("LoadStandardKey() should return non-nil key")
	}
}

func TestU_LoadStandardKey_InvalidPath(t *testing.T) {
	_, err := LoadStandardKey("/nonexistent/path/key.pem", "")
	if err == nil {
		t.Error("LoadStandardKey() should fail for non-existent file")
	}
}

// =============================================================================
// LoadPKCS8Key Tests
// =============================================================================

func TestU_LoadPKCS8Key_FallbackToStandard(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "pkcs8.key")

	// Write a PKCS#8 encoded key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8 key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	result, err := LoadPKCS8Key(keyPath, "")
	if err != nil {
		t.Fatalf("LoadPKCS8Key() error = %v", err)
	}

	if result == nil {
		t.Error("LoadPKCS8Key() should return non-nil key")
	}
}
