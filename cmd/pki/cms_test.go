package main

import (
	"os"
	"testing"
)

// =============================================================================
// CMS Sign Tests
// =============================================================================

// TestCMSSign_Basic tests basic CMS signing.
func TestCMSSign_Basic(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Setup
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Hello, CMS!")
	outputPath := tc.path("signature.p7s")

	// Execute
	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", outputPath,
	)
	if err != nil {
		t.Fatalf("CMS sign failed: %v", err)
	}

	// Verify output file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Signature file was not created")
	}

	// Verify signature file has content
	data := tc.readFile("signature.p7s")
	if len(data) == 0 {
		t.Error("Signature file is empty")
	}
}

// TestCMSSign_SHA384 tests CMS signing with SHA-384.
func TestCMSSign_SHA384(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Test with SHA-384")
	outputPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--hash", "sha384",
		"--out", outputPath,
	)
	if err != nil {
		t.Fatalf("CMS sign with SHA-384 failed: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Signature file was not created")
	}
}

// TestCMSSign_SHA512 tests CMS signing with SHA-512.
func TestCMSSign_SHA512(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Test with SHA-512")
	outputPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--hash", "sha512",
		"--out", outputPath,
	)
	if err != nil {
		t.Fatalf("CMS sign with SHA-512 failed: %v", err)
	}

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Signature file was not created")
	}
}

// TestCMSSign_Attached tests CMS signing with attached content.
func TestCMSSign_Attached(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Attached content test")
	outputPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--detached=false",
		"--out", outputPath,
	)
	if err != nil {
		t.Fatalf("CMS sign attached failed: %v", err)
	}

	// Attached signature should be larger (contains content)
	data := tc.readFile("signature.p7s")
	if len(data) < 100 {
		t.Error("Attached signature seems too small")
	}
}

// TestCMSSign_MissingData tests error when data file is missing.
func TestCMSSign_MissingData(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, keyPath := tc.setupSigningPair()
	outputPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", tc.path("nonexistent.txt"),
		"--cert", certPath,
		"--key", keyPath,
		"--out", outputPath,
	)
	if err == nil {
		t.Error("Expected error for missing data file")
	}
}

// TestCMSSign_MissingCert tests error when certificate is missing.
func TestCMSSign_MissingCert(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	_, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test")
	outputPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", tc.path("nonexistent.crt"),
		"--key", keyPath,
		"--out", outputPath,
	)
	if err == nil {
		t.Error("Expected error for missing certificate")
	}
}

// TestCMSSign_MissingKey tests error when key is missing.
func TestCMSSign_MissingKey(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, _ := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test")
	outputPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", tc.path("nonexistent.key"),
		"--out", outputPath,
	)
	if err == nil {
		t.Error("Expected error for missing key")
	}
}

// TestCMSSign_InvalidHash tests error for invalid hash algorithm.
func TestCMSSign_InvalidHash(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "test")
	outputPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--hash", "md5",
		"--out", outputPath,
	)
	if err == nil {
		t.Error("Expected error for invalid hash algorithm")
	}
}

// =============================================================================
// CMS Verify Tests
// =============================================================================

// TestCMSVerify_DetachedSignature tests verifying a detached signature.
func TestCMSVerify_DetachedSignature(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Create signature first
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Content to verify")
	sigPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", sigPath,
	)
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	// Reset flags for verify command
	resetCMSFlags()

	// Verify (skip cert chain verification)
	_, err = executeCommand(rootCmd, "cms", "verify",
		"--signature", sigPath,
		"--data", dataPath,
	)
	if err != nil {
		t.Fatalf("CMS verify failed: %v", err)
	}
}

// TestCMSVerify_AttachedSignature tests verifying an attached signature.
func TestCMSVerify_AttachedSignature(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Create attached signature
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Attached content")
	sigPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--detached=false",
		"--out", sigPath,
	)
	if err != nil {
		t.Fatalf("Failed to create attached signature: %v", err)
	}

	resetCMSFlags()

	// Verify without data (content is in signature)
	_, err = executeCommand(rootCmd, "cms", "verify",
		"--signature", sigPath,
	)
	if err != nil {
		t.Fatalf("CMS verify attached failed: %v", err)
	}
}

// TestCMSVerify_WithCA tests verifying with CA certificate.
// Uses a self-signed cert to avoid EKU/key usage validation issues.
func TestCMSVerify_WithCA(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Use self-signed cert (issuer == subject) for CA verification
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Signed with chain")
	sigPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", sigPath,
	)
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	resetCMSFlags()

	// Verify with the same cert as CA (self-signed)
	_, err = executeCommand(rootCmd, "cms", "verify",
		"--signature", sigPath,
		"--data", dataPath,
		"--ca", certPath,
	)
	if err != nil {
		t.Fatalf("CMS verify with CA failed: %v", err)
	}
}

// TestCMSVerify_MissingSignature tests error when signature file is missing.
func TestCMSVerify_MissingSignature(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	dataPath := tc.writeFile("data.txt", "test")

	_, err := executeCommand(rootCmd, "cms", "verify",
		"--signature", tc.path("nonexistent.p7s"),
		"--data", dataPath,
	)
	if err == nil {
		t.Error("Expected error for missing signature file")
	}
}

// TestCMSVerify_WrongData tests verification fails with wrong data.
func TestCMSVerify_WrongData(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Create signature
	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Original content")
	sigPath := tc.path("signature.p7s")

	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", sigPath,
	)
	if err != nil {
		t.Fatalf("Failed to create signature: %v", err)
	}

	resetCMSFlags()

	// Create different data file
	wrongDataPath := tc.writeFile("wrong.txt", "Different content")

	// Verify with wrong data should fail
	_, err = executeCommand(rootCmd, "cms", "verify",
		"--signature", sigPath,
		"--data", wrongDataPath,
	)
	if err == nil {
		t.Error("Expected error when verifying with wrong data")
	}
}

// =============================================================================
// CMS Sign + Verify Round Trip Tests
// =============================================================================

// TestCMSSignVerify_RoundTrip_ECDSA tests sign and verify round trip.
func TestCMSSignVerify_RoundTrip_ECDSA(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, keyPath := tc.setupSigningPair()
	dataPath := tc.writeFile("data.txt", "Round trip test content")
	sigPath := tc.path("signature.p7s")

	// Sign
	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", sigPath,
	)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	resetCMSFlags()

	// Verify
	_, err = executeCommand(rootCmd, "cms", "verify",
		"--signature", sigPath,
		"--data", dataPath,
	)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

// TestCMSSignVerify_RoundTrip_RSA tests sign and verify with RSA.
func TestCMSSignVerify_RoundTrip_RSA(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	// Generate RSA key pair
	priv, pub := generateRSAKeyPair(tc.t, 2048)
	cert := generateSelfSignedCert(tc.t, priv, pub)
	certPath := tc.writeCertPEM("rsa.crt", cert)
	keyPath := tc.writeKeyPEM("rsa.key", priv)

	dataPath := tc.writeFile("data.txt", "RSA round trip test")
	sigPath := tc.path("signature.p7s")

	// Sign
	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", sigPath,
	)
	if err != nil {
		t.Fatalf("RSA Sign failed: %v", err)
	}

	resetCMSFlags()

	// Verify
	_, err = executeCommand(rootCmd, "cms", "verify",
		"--signature", sigPath,
		"--data", dataPath,
	)
	if err != nil {
		t.Fatalf("RSA Verify failed: %v", err)
	}
}

// TestCMSSignVerify_LargeFile tests signing a larger file.
func TestCMSSignVerify_LargeFile(t *testing.T) {
	tc := newTestContext(t)
	resetCMSFlags()

	certPath, keyPath := tc.setupSigningPair()

	// Create 10KB file
	largeContent := make([]byte, 10*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	dataPath := tc.path("large.bin")
	if err := os.WriteFile(dataPath, largeContent, 0644); err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	sigPath := tc.path("signature.p7s")

	// Sign
	_, err := executeCommand(rootCmd, "cms", "sign",
		"--data", dataPath,
		"--cert", certPath,
		"--key", keyPath,
		"--out", sigPath,
	)
	if err != nil {
		t.Fatalf("Sign large file failed: %v", err)
	}

	resetCMSFlags()

	// Verify
	_, err = executeCommand(rootCmd, "cms", "verify",
		"--signature", sigPath,
		"--data", dataPath,
	)
	if err != nil {
		t.Fatalf("Verify large file failed: %v", err)
	}
}
