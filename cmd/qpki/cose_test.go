package main

import (
	"encoding/pem"
	"os"
	"testing"

	gocose "github.com/veraison/go-cose"

	"github.com/qpki/qpki/internal/cose"
)

// Note: t.Parallel() is not used because Cobra commands share global flag state.

// =============================================================================
// loadCertPoolWithCerts Tests
// =============================================================================

func TestU_loadCertPoolWithCerts(t *testing.T) {
	t.Run("[Unit] loadCertPoolWithCerts: loads valid certificate", func(t *testing.T) {
		tc := newTestContext(t)
		priv, pub := generateECDSAKeyPair(t)
		cert := generateSelfSignedCert(t, priv, pub)

		certPath := tc.writeCertPEM("ca.pem", cert)

		pool, certs, err := loadCertPoolWithCerts(certPath)
		if err != nil {
			t.Fatalf("loadCertPoolWithCerts() error = %v", err)
		}

		if pool == nil {
			t.Error("loadCertPoolWithCerts() returned nil pool")
		}
		if len(certs) != 1 {
			t.Errorf("loadCertPoolWithCerts() returned %d certs, want 1", len(certs))
		}
	})

	t.Run("[Unit] loadCertPoolWithCerts: loads multiple certificates", func(t *testing.T) {
		tc := newTestContext(t)
		priv1, pub1 := generateECDSAKeyPair(t)
		cert1 := generateSelfSignedCert(t, priv1, pub1)
		priv2, pub2 := generateECDSAKeyPair(t)
		cert2 := generateSelfSignedCert(t, priv2, pub2)

		var certPEM []byte
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert1.Raw,
		})...)
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert2.Raw,
		})...)

		certPath := tc.writeFile("ca.pem", string(certPEM))

		pool, certs, err := loadCertPoolWithCerts(certPath)
		if err != nil {
			t.Fatalf("loadCertPoolWithCerts() error = %v", err)
		}

		if pool == nil {
			t.Error("loadCertPoolWithCerts() returned nil pool")
		}
		if len(certs) != 2 {
			t.Errorf("loadCertPoolWithCerts() returned %d certs, want 2", len(certs))
		}
	})

	t.Run("[Unit] loadCertPoolWithCerts: fails for non-existent file", func(t *testing.T) {
		_, _, err := loadCertPoolWithCerts("/nonexistent/ca.pem")
		if err == nil {
			t.Error("loadCertPoolWithCerts() should fail for non-existent file")
		}
	})

	t.Run("[Unit] loadCertPoolWithCerts: fails for empty file", func(t *testing.T) {
		tc := newTestContext(t)
		certPath := tc.writeFile("empty.pem", "")

		_, _, err := loadCertPoolWithCerts(certPath)
		if err == nil {
			t.Error("loadCertPoolWithCerts() should fail for empty file")
		}
	})

	t.Run("[Unit] loadCertPoolWithCerts: fails for invalid PEM", func(t *testing.T) {
		tc := newTestContext(t)
		certPath := tc.writeFile("invalid.pem", "not valid PEM content")

		_, _, err := loadCertPoolWithCerts(certPath)
		if err == nil {
			t.Error("loadCertPoolWithCerts() should fail for invalid PEM")
		}
	})

	t.Run("[Unit] loadCertPoolWithCerts: skips non-certificate blocks", func(t *testing.T) {
		tc := newTestContext(t)
		priv, pub := generateECDSAKeyPair(t)
		cert := generateSelfSignedCert(t, priv, pub)

		var data []byte
		// Add a private key block (should be skipped)
		data = append(data, pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: []byte("fake key data"),
		})...)
		// Add the certificate
		data = append(data, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)

		certPath := tc.writeFile("mixed.pem", string(data))

		pool, certs, err := loadCertPoolWithCerts(certPath)
		if err != nil {
			t.Fatalf("loadCertPoolWithCerts() error = %v", err)
		}

		if len(certs) != 1 {
			t.Errorf("loadCertPoolWithCerts() returned %d certs, want 1", len(certs))
		}
		if pool == nil {
			t.Error("loadCertPoolWithCerts() returned nil pool")
		}
	})
}

// =============================================================================
// COSE Sign Command Flags Tests
// =============================================================================

func TestU_COSESign_FlagValidation(t *testing.T) {
	t.Run("[Unit] COSESign: requires output flag", func(t *testing.T) {
		tc := newTestContext(t)
		resetCOSESignFlags()

		certPath, keyPath := tc.setupSigningPair()

		rootCmd.SetArgs([]string{"cose", "sign",
			"--type", "cwt",
			"--iss", "https://issuer.example.com",
			"--sub", "user-42",
			"--cert", certPath,
			"--key", keyPath,
			// Missing --out flag
		})

		err := rootCmd.Execute()
		if err == nil {
			t.Error("cose sign should fail without --out flag")
		}
	})

	t.Run("[Unit] COSESign: invalid message type", func(t *testing.T) {
		tc := newTestContext(t)
		resetCOSESignFlags()

		certPath, keyPath := tc.setupSigningPair()
		outputPath := tc.path("token.cbor")

		rootCmd.SetArgs([]string{"cose", "sign",
			"--type", "invalid",
			"--iss", "https://issuer.example.com",
			"--cert", certPath,
			"--key", keyPath,
			"--out", outputPath,
		})

		err := rootCmd.Execute()
		if err == nil {
			t.Error("cose sign should fail with invalid message type")
		}
	})
}

// =============================================================================
// COSE Verify Command Tests
// =============================================================================

func TestU_COSEVerify_FlagValidation(t *testing.T) {
	t.Run("[Unit] COSEVerify: fails for non-existent file", func(t *testing.T) {
		rootCmd.SetArgs([]string{"cose", "verify", "/nonexistent/token.cbor"})
		err := rootCmd.Execute()
		if err == nil {
			t.Error("cose verify should fail for non-existent file")
		}
	})
}

// =============================================================================
// COSE Info Command Tests
// =============================================================================

func TestU_COSEInfo_FlagValidation(t *testing.T) {
	t.Run("[Unit] COSEInfo: fails for non-existent file", func(t *testing.T) {
		rootCmd.SetArgs([]string{"cose", "info", "/nonexistent/token.cbor"})
		err := rootCmd.Execute()
		if err == nil {
			t.Error("cose info should fail for non-existent file")
		}
	})
}

// =============================================================================
// Functional COSE Sign Tests
// =============================================================================

func TestF_COSE_Sign_CWT(t *testing.T) {
	t.Run("[Functional] COSESign: creates CWT with claims", func(t *testing.T) {
		tc := newTestContext(t)
		resetCOSESignFlags()

		certPath, keyPath := tc.setupSigningPair()
		outputPath := tc.path("token.cbor")

		rootCmd.SetArgs([]string{"cose", "sign",
			"--type", "cwt",
			"--iss", "https://issuer.example.com",
			"--sub", "user-42",
			"--exp", "1h",
			"--cert", certPath,
			"--key", keyPath,
			"--out", outputPath,
		})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("cose sign failed: %v", err)
		}

		// Verify output file exists and has content
		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}
		if len(data) == 0 {
			t.Error("output file is empty")
		}
	})

	t.Run("[Functional] COSESign: creates CWT with custom claims", func(t *testing.T) {
		tc := newTestContext(t)
		resetCOSESignFlags()

		certPath, keyPath := tc.setupSigningPair()
		outputPath := tc.path("token.cbor")

		rootCmd.SetArgs([]string{"cose", "sign",
			"--type", "cwt",
			"--iss", "https://issuer.example.com",
			"--sub", "user-42",
			"--exp", "1h",
			"--claim", "-1=admin",
			"--claim", "-2=tenant-acme",
			"--cert", certPath,
			"--key", keyPath,
			"--out", outputPath,
		})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("cose sign failed: %v", err)
		}

		// Verify output file exists
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("output file was not created")
		}
	})
}

func TestF_COSE_Sign_Sign1(t *testing.T) {
	t.Run("[Functional] COSESign: creates Sign1 message", func(t *testing.T) {
		tc := newTestContext(t)
		resetCOSESignFlags()

		certPath, keyPath := tc.setupSigningPair()
		dataPath := tc.writeFile("data.txt", "Test content for signing")
		outputPath := tc.path("signed.cbor")

		rootCmd.SetArgs([]string{"cose", "sign",
			"--type", "sign1",
			"--data", dataPath,
			"--cert", certPath,
			"--key", keyPath,
			"--out", outputPath,
		})

		err := rootCmd.Execute()
		if err != nil {
			t.Fatalf("cose sign failed: %v", err)
		}

		// Verify output file exists and has content
		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read output: %v", err)
		}
		if len(data) == 0 {
			t.Error("output file is empty")
		}
	})

	t.Run("[Functional] COSESign: fails without data for sign1", func(t *testing.T) {
		tc := newTestContext(t)
		resetCOSESignFlags()

		certPath, keyPath := tc.setupSigningPair()
		outputPath := tc.path("signed.cbor")

		rootCmd.SetArgs([]string{"cose", "sign",
			"--type", "sign1",
			// Missing --data
			"--cert", certPath,
			"--key", keyPath,
			"--out", outputPath,
		})

		err := rootCmd.Execute()
		if err == nil {
			t.Error("cose sign --type sign1 should fail without --data")
		}
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

func resetCOSESignFlags() {
	coseSignType = "cwt"
	coseSignData = ""
	coseSignCert = ""
	coseSignKey = ""
	coseSignPQCCert = ""
	coseSignPQCKey = ""
	coseSignPassphrase = ""
	coseSignOutput = ""
	coseSignIss = ""
	coseSignSub = ""
	coseSignAud = ""
	coseSignExp = ""
	coseSignClaims = nil
	coseSignIncludeCerts = false
	coseSignHSMConfig = ""
	coseSignKeyLabel = ""
	coseSignKeyID = ""
	coseSignCredential = ""
	coseSignCredDir = "./credentials"
}

// =============================================================================
// COSE Sign + Verify Round Trip
// =============================================================================

func TestF_COSE_SignVerify_CWT(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	certPath, keyPath := tc.setupSigningPair()
	outputPath := tc.path("token.cbor")

	// Sign CWT
	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "cwt",
		"--iss", "https://issuer.example.com",
		"--sub", "user-42",
		"--aud", "https://audience.example.com",
		"--exp", "1h",
		"--cert", certPath,
		"--key", keyPath,
		"--out", outputPath,
	})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("cose sign failed: %v", err)
	}

	// Verify CWT
	coseVerifyCert = ""
	coseVerifyCA = ""
	coseVerifyData = ""
	coseVerifyNoCheckExp = false

	rootCmd.SetArgs([]string{"cose", "verify",
		outputPath,
		"--cert", certPath,
		"--no-check-exp",
	})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("cose verify failed: %v", err)
	}
}

func TestF_COSE_SignVerify_Sign1(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Test content for signing")
	outputPath := tc.path("signed.cbor")

	// Sign
	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "sign1",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", outputPath,
	})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("cose sign failed: %v", err)
	}

	// Verify
	coseVerifyCert = ""
	coseVerifyCA = ""
	coseVerifyData = ""
	coseVerifyNoCheckExp = false

	rootCmd.SetArgs([]string{"cose", "verify",
		outputPath,
		"--cert", certPath,
	})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("cose verify failed: %v", err)
	}
}

// =============================================================================
// COSE Info Round Trip
// =============================================================================

func TestF_COSE_Info_CWT(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	certPath, keyPath := tc.setupSigningPair()
	outputPath := tc.path("token.cbor")

	// Create a CWT first
	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "cwt",
		"--iss", "https://issuer.example.com",
		"--sub", "user-42",
		"--exp", "1h",
		"--cert", certPath,
		"--key", keyPath,
		"--out", outputPath,
	})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("cose sign failed: %v", err)
	}

	// Get info
	rootCmd.SetArgs([]string{"cose", "info", outputPath})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("cose info failed: %v", err)
	}
}

// =============================================================================
// COSE Sign With Include Certs
// =============================================================================

func TestF_COSE_Sign_WithIncludeCerts(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	certPath, keyPath := tc.setupSigningPair()
	outputPath := tc.path("token.cbor")

	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "cwt",
		"--iss", "https://issuer.example.com",
		"--sub", "user-42",
		"--exp", "1h",
		"--cert", certPath,
		"--key", keyPath,
		"--include-certs",
		"--out", outputPath,
	})

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("cose sign with include-certs failed: %v", err)
	}

	assertFileExists(t, outputPath)
}

// =============================================================================
// COSE Sign Error Cases
// =============================================================================

func TestF_COSE_Sign_InvalidClaimFormat(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	certPath, keyPath := tc.setupSigningPair()
	outputPath := tc.path("token.cbor")

	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "cwt",
		"--iss", "https://issuer.example.com",
		"--claim", "badformat",
		"--cert", certPath,
		"--key", keyPath,
		"--out", outputPath,
	})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("cose sign should fail with invalid claim format")
	}
}

func TestF_COSE_Sign_NonIntegerClaimKey(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	certPath, keyPath := tc.setupSigningPair()
	outputPath := tc.path("token.cbor")

	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "cwt",
		"--iss", "https://issuer.example.com",
		"--claim", "notanumber=value",
		"--cert", certPath,
		"--key", keyPath,
		"--out", outputPath,
	})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("cose sign should fail with non-integer claim key")
	}
}

func TestF_COSE_Sign_NoSigningKey(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	outputPath := tc.path("token.cbor")

	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "cwt",
		"--iss", "https://issuer.example.com",
		"--out", outputPath,
	})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("cose sign should fail without signing key")
	}
}

func TestF_COSE_Sign_InvalidExpDuration(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	certPath, keyPath := tc.setupSigningPair()
	outputPath := tc.path("token.cbor")

	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "cwt",
		"--iss", "https://issuer.example.com",
		"--exp", "notaduration",
		"--cert", certPath,
		"--key", keyPath,
		"--out", outputPath,
	})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("cose sign should fail with invalid expiration duration")
	}
}

func TestF_COSE_Sign_CertNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetCOSESignFlags()

	outputPath := tc.path("token.cbor")

	rootCmd.SetArgs([]string{"cose", "sign",
		"--type", "cwt",
		"--iss", "https://issuer.example.com",
		"--cert", tc.path("nonexistent.crt"),
		"--key", tc.path("nonexistent.key"),
		"--out", outputPath,
	})

	err := rootCmd.Execute()
	if err == nil {
		t.Error("cose sign should fail with nonexistent cert")
	}
}

// =============================================================================
// COSE Verify Error Cases
// =============================================================================

func TestF_COSE_Verify_InvalidData(t *testing.T) {
	tc := newTestContext(t)
	coseVerifyCert = ""
	coseVerifyCA = ""
	coseVerifyData = ""
	coseVerifyNoCheckExp = false

	invalidPath := tc.writeFile("invalid.cbor", "not valid CBOR data")

	rootCmd.SetArgs([]string{"cose", "verify", invalidPath})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("cose verify should fail with invalid data")
	}
}

func TestF_COSE_Info_InvalidData(t *testing.T) {
	tc := newTestContext(t)

	invalidPath := tc.writeFile("invalid.cbor", "not valid CBOR data")

	rootCmd.SetArgs([]string{"cose", "info", invalidPath})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("cose info should fail with invalid data")
	}
}

// =============================================================================
// printCOSEVerificationResult Unit Test
// =============================================================================

func TestU_PrintCOSEVerificationResult(t *testing.T) {
	// Just test that it doesn't panic with various inputs
	t.Run("valid result", func(t *testing.T) {
		result := &cose.VerifyResult{
			Valid:      true,
			Mode:       cose.ModeClassical,
			Algorithms: []gocose.Algorithm{gocose.AlgorithmES256},
		}
		printCOSEVerificationResult(result) // should not panic
	})

	t.Run("invalid result with warnings", func(t *testing.T) {
		result := &cose.VerifyResult{
			Valid:      false,
			Mode:       cose.ModeClassical,
			Algorithms: []gocose.Algorithm{gocose.AlgorithmES256},
			Warnings:   []string{"signature mismatch", "expired"},
		}
		printCOSEVerificationResult(result) // should not panic
	})

	t.Run("result with claims", func(t *testing.T) {
		claims := cose.NewClaims()
		claims.Issuer = "https://issuer.example.com"
		claims.Subject = "user-42"
		result := &cose.VerifyResult{
			Valid:      true,
			Mode:       cose.ModeClassical,
			Algorithms: []gocose.Algorithm{gocose.AlgorithmES256},
			Claims:     claims,
		}
		printCOSEVerificationResult(result) // should not panic
	})
}
