package cms

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"testing"
)

// =============================================================================
// PHASE 0: Algorithm Confusion Security Tests (TDD - must FAIL before fix)
// =============================================================================

// TestVerify_UsesOIDNotKeyType tests that verification is driven by the declared
// OID in SignerInfo.SignatureAlgorithm, NOT by the Go key type.
//
// SECURITY: This is the "golden rule" test. The algorithm used for verification
// MUST be determined by the OID (and its parameters), NEVER by the Go key type.
//
// This test creates a valid ECDSA signature, then modifies the OID to RSA.
// If the implementation switches on key type instead of OID, it would verify
// successfully (wrong!). The correct behavior is to REJECT because OID says RSA
// but the key is ECDSA.
func TestVerify_UsesOIDNotKeyType(t *testing.T) {
	// Setup: Create ECDSA key and certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content for algorithm confusion")

	// Sign with ECDSA (legitimate)
	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	}

	signedData, err := Sign(content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify the OID is ECDSA
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Fatalf("Expected ECDSA OID, got %v", oid)
	}

	// ATTACK: Modify the OID to RSA (SHA256WithRSA)
	// The signature is still a valid ECDSA signature, but OID claims RSA
	tamperedData := modifySignedDataOID(t, signedData, OIDSHA256WithRSA)

	// Verify should FAIL because OID says RSA but key is ECDSA
	// If this passes, we have an algorithm confusion vulnerability!
	_, err = Verify(tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY VULNERABILITY: Verification succeeded despite OID/key type mismatch. " +
			"The implementation switches on Go key type instead of validating OID. " +
			"This allows algorithm confusion attacks (CVE-2024-49958, CVE-2022-21449)")
	}

	// The error should indicate algorithm mismatch
	t.Logf("Correctly rejected with error: %v", err)
}

// TestVerify_Mismatch_RSADeclared_ECDSAKey tests that RSA OID with ECDSA key is rejected.
func TestVerify_Mismatch_RSADeclared_ECDSAKey(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	// Sign with ECDSA
	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to RSA
	tamperedData := modifySignedDataOID(t, signedData, OIDSHA256WithRSA)

	// Must fail - OID says RSA, key is ECDSA
	_, err = Verify(tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject RSA OID with ECDSA key")
	}
	t.Logf("Correctly rejected RSA/ECDSA mismatch: %v", err)
}

// TestVerify_Mismatch_ECDSADeclared_RSAKey tests that ECDSA OID with RSA key is rejected.
func TestVerify_Mismatch_ECDSADeclared_RSAKey(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	// Sign with RSA
	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to ECDSA
	tamperedData := modifySignedDataOID(t, signedData, OIDECDSAWithSHA256)

	// Must fail - OID says ECDSA, key is RSA
	_, err = Verify(tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject ECDSA OID with RSA key")
	}
	t.Logf("Correctly rejected ECDSA/RSA mismatch: %v", err)
}

// TestVerify_Mismatch_Ed25519Declared_ECDSAKey tests Ed25519 OID with ECDSA key.
func TestVerify_Mismatch_Ed25519Declared_ECDSAKey(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to Ed25519
	tamperedData := modifySignedDataOID(t, signedData, OIDEd25519)

	_, err = Verify(tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject Ed25519 OID with ECDSA key")
	}
	t.Logf("Correctly rejected Ed25519/ECDSA mismatch: %v", err)
}

// TestVerify_Mismatch_CurveMismatch_P256_P384 tests curve mismatch detection.
func TestVerify_Mismatch_CurveMismatch_P256_P384(t *testing.T) {
	// Sign with P-256
	kpP256 := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kpP256)

	content := []byte("test content")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kpP256.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to ECDSA-SHA384 (implies P-384)
	tamperedData := modifySignedDataOID(t, signedData, OIDECDSAWithSHA384)

	// Should fail - hash algorithm mismatch (SHA256 was used, but OID says SHA384)
	_, err = Verify(tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject hash algorithm mismatch")
	}
	t.Logf("Correctly rejected curve/hash mismatch: %v", err)
}

// TestVerify_Mismatch_MLDSADeclared_ECDSAKey tests ML-DSA OID with ECDSA key.
func TestVerify_Mismatch_MLDSADeclared_ECDSAKey(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper: Change OID to ML-DSA-65
	tamperedData := modifySignedDataOID(t, signedData, OIDMLDSA65)

	_, err = Verify(tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject ML-DSA OID with ECDSA key")
	}
	t.Logf("Correctly rejected ML-DSA/ECDSA mismatch: %v", err)
}

// =============================================================================
// PHASE 1: Basic Sign/Verify Tests
// =============================================================================

// TestSign_Verify_ECDSA_P256 tests ECDSA P-256 sign and verify round trip.
func TestSign_Verify_ECDSA_P256(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	}

	// Sign
	signedData, err := Sign(content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify OID matches expected algorithm
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("OID mismatch: expected ECDSA-SHA256, got %v", oid)
	}

	// Verify
	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if result.SignerCert == nil {
		t.Error("SignerCert is nil")
	}

	// Verify content matches
	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch: expected %q, got %q", content, result.Content)
	}
}

// TestSign_Verify_ECDSA_P384 tests ECDSA P-384 sign and verify round trip.
func TestSign_Verify_ECDSA_P384(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P384())
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with P-384!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	}

	signedData, err := Sign(content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA384) {
		t.Errorf("OID mismatch: expected ECDSA-SHA384, got %v", oid)
	}

	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// TestSign_Verify_RSA tests RSA sign and verify round trip.
func TestSign_Verify_RSA(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with RSA!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	}

	signedData, err := Sign(content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("OID mismatch: expected RSA-SHA256, got %v", oid)
	}

	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// TestSign_Verify_Ed25519 tests Ed25519 sign and verify round trip.
func TestSign_Verify_Ed25519(t *testing.T) {
	kp := generateEd25519KeyPair(t)
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with Ed25519!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	}

	signedData, err := Sign(content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd25519) {
		t.Errorf("OID mismatch: expected Ed25519, got %v", oid)
	}

	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// =============================================================================
// PHASE 1: Detached Signatures Tests
// =============================================================================

// TestSign_Verify_Detached_ECDSA tests detached ECDSA signature.
func TestSign_Verify_Detached_ECDSA(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Detached content for ECDSA")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	}

	signedData, err := Sign(content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify OID
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("OID mismatch: expected ECDSA-SHA256, got %v", oid)
	}

	// Verify with detached content
	result, err := Verify(signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	// Content should not be in the result (detached)
	if result.Content != nil {
		t.Error("Expected nil content for detached signature")
	}
}

// TestSign_Verify_Detached_RSA tests detached RSA signature.
func TestSign_Verify_Detached_RSA(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("Detached content for RSA")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	}

	signedData, err := Sign(content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("OID mismatch: expected RSA-SHA256, got %v", oid)
	}

	_, err = Verify(signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}
}

// =============================================================================
// PHASE 1: Negative Tests (Invalid Signatures)
// =============================================================================

// TestVerify_InvalidSignature tests that tampered signatures are rejected.
func TestVerify_InvalidSignature(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Content to tamper")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper with signature
	tamperedData := modifySignature(t, signedData)

	_, err = Verify(tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("Verification should fail for tampered signature")
	}
	t.Logf("Correctly rejected tampered signature: %v", err)
}

// TestVerify_InvalidMessageDigest tests that tampered message digest is rejected.
func TestVerify_InvalidMessageDigest(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Content with digest to tamper")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Tamper with message digest
	tamperedData := modifyMessageDigest(t, signedData)

	_, err = Verify(tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("Verification should fail for tampered message digest")
	}
	t.Logf("Correctly rejected tampered message digest: %v", err)
}

// TestVerify_WrongDetachedContent tests wrong content for detached signature.
func TestVerify_WrongDetachedContent(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	originalContent := []byte("Original content")
	wrongContent := []byte("Wrong content")

	signedData, err := Sign(originalContent, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify with wrong content
	_, err = Verify(signedData, &VerifyConfig{
		Data:           wrongContent,
		SkipCertVerify: true,
	})
	if err == nil {
		t.Fatal("Verification should fail for wrong detached content")
	}
	t.Logf("Correctly rejected wrong content: %v", err)
}

// =============================================================================
// PHASE 1: Certificate Chain Verification Tests
// =============================================================================

// TestVerify_CertificateChain tests certificate chain verification.
func TestVerify_CertificateChain(t *testing.T) {
	// Create CA
	caCert, caKey := generateTestCA(t)

	// Create end entity key and certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	content := []byte("Content with chain verification")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	// Verify with chain
	result, err := Verify(signedData, &VerifyConfig{
		Roots: roots,
	})
	if err != nil {
		t.Fatalf("Failed to verify with chain: %v", err)
	}

	if result.SignerCert == nil {
		t.Error("SignerCert is nil")
	}
}

// TestVerify_UntrustedCertificate tests that untrusted certificates are rejected.
func TestVerify_UntrustedCertificate(t *testing.T) {
	// Create two different CAs
	trustedCACert, _ := generateTestCA(t)
	untrustedCACert, untrustedCAKey := generateTestCA(t)

	// Create end entity key and certificate signed by untrusted CA
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, untrustedCACert, untrustedCAKey, kp)

	content := []byte("Content from untrusted source")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Create root pool with only trusted CA
	roots := x509.NewCertPool()
	roots.AddCert(trustedCACert)

	// Verify should fail - certificate is not from trusted CA
	_, err = Verify(signedData, &VerifyConfig{
		Roots: roots,
	})
	if err == nil {
		t.Fatal("Verification should fail for untrusted certificate")
	}
	t.Logf("Correctly rejected untrusted certificate: %v", err)
}
