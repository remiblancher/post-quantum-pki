package cms

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	pkicrypto "github.com/remiblancher/post-quantum-pki/internal/crypto"
)

// =============================================================================
// Security Tests: Algorithm Confusion (TDD - must FAIL before fix)
// =============================================================================

// TestF_Verify_AlgorithmConfusion_OIDNotKeyType tests that verification is driven by the declared
// OID in SignerInfo.SignatureAlgorithm, NOT by the Go key type.
//
// SECURITY: This is the "golden rule" test. The algorithm used for verification
// MUST be determined by the OID (and its parameters), NEVER by the Go key type.
//
// This test creates a valid ECDSA signature, then modifies the OID to RSA.
// If the implementation switches on key type instead of OID, it would verify
// successfully (wrong!). The correct behavior is to REJECT because OID says RSA
// but the key is ECDSA.
func TestF_Verify_AlgorithmConfusion_OIDNotKeyType(t *testing.T) {
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

	signedData, err := Sign(context.Background(), content, signConfig)
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
	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY VULNERABILITY: Verification succeeded despite OID/key type mismatch. " +
			"The implementation switches on Go key type instead of validating OID. " +
			"This allows algorithm confusion attacks (CVE-2024-49958, CVE-2022-21449)")
	}

	// The error should indicate algorithm mismatch
	t.Logf("Correctly rejected with error: %v", err)
}

// TestF_Verify_AlgorithmMismatch_RSADeclaredECDSAKey tests that RSA OID with ECDSA key is rejected.
func TestF_Verify_AlgorithmMismatch_RSADeclaredECDSAKey(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	// Sign with ECDSA
	signedData, err := Sign(context.Background(), content, &SignerConfig{
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
	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject RSA OID with ECDSA key")
	}
	t.Logf("Correctly rejected RSA/ECDSA mismatch: %v", err)
}

// TestF_Verify_AlgorithmMismatch_ECDSADeclaredRSAKey tests that ECDSA OID with RSA key is rejected.
func TestF_Verify_AlgorithmMismatch_ECDSADeclaredRSAKey(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	// Sign with RSA
	signedData, err := Sign(context.Background(), content, &SignerConfig{
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
	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject ECDSA OID with RSA key")
	}
	t.Logf("Correctly rejected ECDSA/RSA mismatch: %v", err)
}

// TestF_Verify_AlgorithmMismatch_Ed25519DeclaredECDSAKey tests Ed25519 OID with ECDSA key.
func TestF_Verify_AlgorithmMismatch_Ed25519DeclaredECDSAKey(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
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

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject Ed25519 OID with ECDSA key")
	}
	t.Logf("Correctly rejected Ed25519/ECDSA mismatch: %v", err)
}

// TestF_Verify_AlgorithmMismatch_CurveP256vsP384 tests curve mismatch detection.
func TestF_Verify_AlgorithmMismatch_CurveP256vsP384(t *testing.T) {
	// Sign with P-256
	kpP256 := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kpP256)

	content := []byte("test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
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
	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject hash algorithm mismatch")
	}
	t.Logf("Correctly rejected curve/hash mismatch: %v", err)
}

// TestF_Verify_AlgorithmMismatch_MLDSADeclaredECDSAKey tests ML-DSA OID with ECDSA key.
func TestF_Verify_AlgorithmMismatch_MLDSADeclaredECDSAKey(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
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

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("SECURITY: Should reject ML-DSA OID with ECDSA key")
	}
	t.Logf("Correctly rejected ML-DSA/ECDSA mismatch: %v", err)
}

// =============================================================================
// Functional Tests: Basic Sign/Verify Round-trip
// =============================================================================

// TestF_SignVerify_ECDSAP256 tests ECDSA P-256 sign and verify round trip.
func TestF_SignVerify_ECDSAP256(t *testing.T) {
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
	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify OID matches expected algorithm
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("OID mismatch: expected ECDSA-SHA256, got %v", oid)
	}

	// Verify
	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
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

// TestF_SignVerify_ECDSAP384 tests ECDSA P-384 sign and verify round trip.
func TestF_SignVerify_ECDSAP384(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P384())
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with P-384!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA384) {
		t.Errorf("OID mismatch: expected ECDSA-SHA384, got %v", oid)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// TestF_SignVerify_RSA tests RSA sign and verify round trip.
func TestF_SignVerify_RSA(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with RSA!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("OID mismatch: expected RSA-SHA256, got %v", oid)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// TestF_SignVerify_Ed25519 tests Ed25519 sign and verify round trip.
func TestF_SignVerify_Ed25519(t *testing.T) {
	kp := generateEd25519KeyPair(t)
	cert := generateTestCertificate(t, kp)

	content := []byte("Hello, CMS with Ed25519!")

	signConfig := &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	}

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd25519) {
		t.Errorf("OID mismatch: expected Ed25519, got %v", oid)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if string(result.Content) != string(content) {
		t.Errorf("Content mismatch")
	}
}

// =============================================================================
// Functional Tests: Detached Signatures
// =============================================================================

// TestF_SignVerify_DetachedECDSA tests detached ECDSA signature.
func TestF_SignVerify_DetachedECDSA(t *testing.T) {
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

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Verify OID
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("OID mismatch: expected ECDSA-SHA256, got %v", oid)
	}

	// Verify with detached content
	result, err := Verify(context.Background(), signedData, &VerifyConfig{
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

// TestF_SignVerify_DetachedRSA tests detached RSA signature.
func TestF_SignVerify_DetachedRSA(t *testing.T) {
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

	signedData, err := Sign(context.Background(), content, signConfig)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("OID mismatch: expected RSA-SHA256, got %v", oid)
	}

	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}
}

// =============================================================================
// Unit Tests: Invalid Signatures (Negative Tests)
// =============================================================================

// TestU_Verify_SignatureInvalid tests that tampered signatures are rejected.
func TestU_Verify_SignatureInvalid(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Content to tamper")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
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

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("Verification should fail for tampered signature")
	}
	t.Logf("Correctly rejected tampered signature: %v", err)
}

// TestU_Verify_MessageDigestInvalid tests that tampered message digest is rejected.
func TestU_Verify_MessageDigestInvalid(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("Content with digest to tamper")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
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

	_, err = Verify(context.Background(), tamperedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Fatal("Verification should fail for tampered message digest")
	}
	t.Logf("Correctly rejected tampered message digest: %v", err)
}

// TestU_Verify_WrongDetachedContent tests wrong content for detached signature.
func TestU_Verify_WrongDetachedContent(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	originalContent := []byte("Original content")
	wrongContent := []byte("Wrong content")

	signedData, err := Sign(context.Background(), originalContent, &SignerConfig{
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
	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Data:           wrongContent,
		SkipCertVerify: true,
	})
	if err == nil {
		t.Fatal("Verification should fail for wrong detached content")
	}
	t.Logf("Correctly rejected wrong content: %v", err)
}

// =============================================================================
// Functional Tests: Certificate Chain Verification
// =============================================================================

// TestF_Verify_CertificateChain tests certificate chain verification.
func TestF_Verify_CertificateChain(t *testing.T) {
	// Create CA
	caCert, caKey := generateTestCA(t)

	// Create end entity key and certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	content := []byte("Content with chain verification")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
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
	result, err := Verify(context.Background(), signedData, &VerifyConfig{
		Roots: roots,
	})
	if err != nil {
		t.Fatalf("Failed to verify with chain: %v", err)
	}

	if result.SignerCert == nil {
		t.Error("SignerCert is nil")
	}
}

// TestU_Verify_CertificateUntrusted tests that untrusted certificates are rejected.
func TestU_Verify_CertificateUntrusted(t *testing.T) {
	// Create two different CAs
	trustedCACert, _ := generateTestCA(t)
	untrustedCACert, untrustedCAKey := generateTestCA(t)

	// Create end entity key and certificate signed by untrusted CA
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, untrustedCACert, untrustedCAKey, kp)

	content := []byte("Content from untrusted source")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
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
	_, err = Verify(context.Background(), signedData, &VerifyConfig{
		Roots: roots,
	})
	if err == nil {
		t.Fatal("Verification should fail for untrusted certificate")
	}
	t.Logf("Correctly rejected untrusted certificate: %v", err)
}

// =============================================================================
// Unit Tests: Algorithm Validation Helpers
// =============================================================================

// TestU_ValidatePQCKeyMatch tests the validatePQCKeyMatch function.
func TestU_ValidatePQCKeyMatch(t *testing.T) {
	// Generate ML-DSA key for testing
	mldsaKP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)

	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		pub         crypto.PublicKey
		expectError bool
	}{
		{
			name:        "[Unit] PQCKeyMatch: ML-DSA-65 OID with ML-DSA-65 key",
			sigAlgOID:   OIDMLDSA65,
			pub:         mldsaKP.PublicKey,
			expectError: false,
		},
		{
			name:        "[Unit] PQCKeyMatch: SLH-DSA-128f OID (valid SLH-DSA)",
			sigAlgOID:   OIDSLHDSA128f,
			pub:         nil, // SLH-DSA validation doesn't check key
			expectError: false,
		},
		{
			name:        "[Unit] PQCKeyMatch: SLH-DSA-128s OID (valid SLH-DSA)",
			sigAlgOID:   OIDSLHDSA128s,
			pub:         nil,
			expectError: false,
		},
		{
			name:        "[Unit] PQCKeyMatch: Unknown OID",
			sigAlgOID:   asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			pub:         mldsaKP.PublicKey,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePQCKeyMatch(tt.sigAlgOID, tt.pub)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_ValidateMLDSAKeyMatch tests the validateMLDSAKeyMatch function.
func TestU_ValidateMLDSAKeyMatch(t *testing.T) {
	// Generate ML-DSA keys for testing
	mldsa44KP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA44)
	mldsa65KP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	mldsa87KP := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA87)

	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		pub         crypto.PublicKey
		expectError bool
	}{
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-44 OID with ML-DSA-44 key",
			sigAlgOID:   OIDMLDSA44,
			pub:         mldsa44KP.PublicKey,
			expectError: false,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-65 OID with ML-DSA-65 key",
			sigAlgOID:   OIDMLDSA65,
			pub:         mldsa65KP.PublicKey,
			expectError: false,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-87 OID with ML-DSA-87 key",
			sigAlgOID:   OIDMLDSA87,
			pub:         mldsa87KP.PublicKey,
			expectError: false,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-44 OID with ML-DSA-65 key (mismatch)",
			sigAlgOID:   OIDMLDSA44,
			pub:         mldsa65KP.PublicKey,
			expectError: true,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: ML-DSA-65 OID with ML-DSA-87 key (mismatch)",
			sigAlgOID:   OIDMLDSA65,
			pub:         mldsa87KP.PublicKey,
			expectError: true,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: Non-ML-DSA OID",
			sigAlgOID:   OIDECDSAWithSHA256,
			pub:         mldsa65KP.PublicKey,
			expectError: true,
		},
		{
			name:        "[Unit] MLDSAKeyMatch: Nil key (should pass if OID is valid)",
			sigAlgOID:   OIDMLDSA65,
			pub:         nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMLDSAKeyMatch(tt.sigAlgOID, tt.pub)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_IsSLHDSAOID tests the isSLHDSAOID function.
func TestU_IsSLHDSAOID(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected bool
	}{
		{"[Unit] isSLHDSAOID: SLH-DSA-128s", OIDSLHDSA128s, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-128f", OIDSLHDSA128f, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-192s", OIDSLHDSA192s, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-192f", OIDSLHDSA192f, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-256s", OIDSLHDSA256s, true},
		{"[Unit] isSLHDSAOID: SLH-DSA-256f", OIDSLHDSA256f, true},
		{"[Unit] isSLHDSAOID: ML-DSA-65 (not SLH-DSA)", OIDMLDSA65, false},
		{"[Unit] isSLHDSAOID: ECDSA-SHA256 (not SLH-DSA)", OIDECDSAWithSHA256, false},
		{"[Unit] isSLHDSAOID: Unknown OID", asn1.ObjectIdentifier{1, 2, 3, 4}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSLHDSAOID(tt.oid)
			if result != tt.expected {
				t.Errorf("isSLHDSAOID(%v) = %v, expected %v", tt.oid, result, tt.expected)
			}
		})
	}
}

// TestU_OidToHash tests the oidToHash function.
func TestU_OidToHash(t *testing.T) {
	tests := []struct {
		name         string
		oid          asn1.ObjectIdentifier
		expectedHash crypto.Hash
		expectError  bool
	}{
		{"[Unit] oidToHash: SHA-256", OIDSHA256, crypto.SHA256, false},
		{"[Unit] oidToHash: SHA-384", OIDSHA384, crypto.SHA384, false},
		{"[Unit] oidToHash: SHA-512", OIDSHA512, crypto.SHA512, false},
		{"[Unit] oidToHash: SHA3-256", OIDSHA3_256, crypto.SHA3_256, false},
		{"[Unit] oidToHash: SHA3-384", OIDSHA3_384, crypto.SHA3_384, false},
		{"[Unit] oidToHash: SHA3-512", OIDSHA3_512, crypto.SHA3_512, false},
		{"[Unit] oidToHash: Unknown OID", asn1.ObjectIdentifier{1, 2, 3}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := oidToHash(tt.oid)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if hash != tt.expectedHash {
					t.Errorf("Hash mismatch: expected %v, got %v", tt.expectedHash, hash)
				}
			}
		})
	}
}

// TestU_ExtractSigningTime tests the extractSigningTime function.
func TestU_ExtractSigningTime(t *testing.T) {
	// Create a signing time attribute
	testTime := time.Date(2024, 6, 15, 12, 30, 45, 0, time.UTC)
	stAttr, err := NewSigningTimeAttr(testTime)
	if err != nil {
		t.Fatalf("Failed to create signing time attr: %v", err)
	}

	tests := []struct {
		name         string
		attrs        []Attribute
		expectedTime time.Time
	}{
		{
			name:         "[Unit] ExtractSigningTime: With signing time",
			attrs:        []Attribute{stAttr},
			expectedTime: testTime,
		},
		{
			name:         "[Unit] ExtractSigningTime: Empty attrs",
			attrs:        []Attribute{},
			expectedTime: time.Time{},
		},
		{
			name: "[Unit] ExtractSigningTime: No signing time attr",
			attrs: []Attribute{
				{Type: OIDContentType, Values: []asn1.RawValue{{FullBytes: []byte{0x06, 0x01, 0x01}}}},
			},
			expectedTime: time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSigningTime(tt.attrs)
			if !result.Equal(tt.expectedTime) {
				t.Errorf("Time mismatch: expected %v, got %v", tt.expectedTime, result)
			}
		})
	}
}

// TestU_ValidateECDSAKeyMatch tests ECDSA OID validation.
func TestU_ValidateECDSAKeyMatch(t *testing.T) {
	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		hashAlg     crypto.Hash
		expectError bool
	}{
		{"[Unit] ECDSAKeyMatch: SHA256 OID with SHA256", OIDECDSAWithSHA256, crypto.SHA256, false},
		{"[Unit] ECDSAKeyMatch: SHA384 OID with SHA384", OIDECDSAWithSHA384, crypto.SHA384, false},
		{"[Unit] ECDSAKeyMatch: SHA512 OID with SHA512", OIDECDSAWithSHA512, crypto.SHA512, false},
		{"[Unit] ECDSAKeyMatch: SHA256 OID with SHA384 (mismatch)", OIDECDSAWithSHA256, crypto.SHA384, true},
		{"[Unit] ECDSAKeyMatch: Non-ECDSA OID", OIDSHA256WithRSA, crypto.SHA256, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateECDSAKeyMatch(tt.sigAlgOID, tt.hashAlg)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_ValidateRSAKeyMatch tests RSA OID validation.
func TestU_ValidateRSAKeyMatch(t *testing.T) {
	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		hashAlg     crypto.Hash
		expectError bool
	}{
		{"[Unit] RSAKeyMatch: SHA256 OID with SHA256", OIDSHA256WithRSA, crypto.SHA256, false},
		{"[Unit] RSAKeyMatch: SHA384 OID with SHA384", OIDSHA384WithRSA, crypto.SHA384, false},
		{"[Unit] RSAKeyMatch: SHA512 OID with SHA512", OIDSHA512WithRSA, crypto.SHA512, false},
		{"[Unit] RSAKeyMatch: SHA256 OID with SHA384 (mismatch)", OIDSHA256WithRSA, crypto.SHA384, true},
		{"[Unit] RSAKeyMatch: Non-RSA OID", OIDECDSAWithSHA256, crypto.SHA256, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRSAKeyMatch(tt.sigAlgOID, tt.hashAlg)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_ValidateEd25519KeyMatch tests Ed25519 OID validation.
func TestU_ValidateEd25519KeyMatch(t *testing.T) {
	tests := []struct {
		name        string
		sigAlgOID   asn1.ObjectIdentifier
		expectError bool
	}{
		{"[Unit] Ed25519KeyMatch: Ed25519 OID", OIDEd25519, false},
		{"[Unit] Ed25519KeyMatch: Non-Ed25519 OID (ECDSA)", OIDECDSAWithSHA256, true},
		{"[Unit] Ed25519KeyMatch: Non-Ed25519 OID (RSA)", OIDSHA256WithRSA, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEd25519KeyMatch(tt.sigAlgOID)
			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestU_GetContent tests the getContent function for detached/attached signatures.
func TestU_GetContent(t *testing.T) {
	attachedContent := []byte("attached content")
	detachedContent := []byte("detached content")

	// Create SignedData with attached content
	sdAttached := &SignedData{
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
			EContent: asn1.RawValue{
				Tag:   asn1.TagOctetString,
				Bytes: attachedContent,
			},
		},
	}

	// Create SignedData without content (for detached)
	sdDetached := &SignedData{
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
		},
	}

	tests := []struct {
		name            string
		signedData      *SignedData
		config          *VerifyConfig
		expectedContent []byte
	}{
		{
			name:            "[Unit] GetContent: Attached content",
			signedData:      sdAttached,
			config:          &VerifyConfig{},
			expectedContent: attachedContent,
		},
		{
			name:       "[Unit] GetContent: Detached content from config",
			signedData: sdDetached,
			config: &VerifyConfig{
				Data: detachedContent,
			},
			expectedContent: detachedContent,
		},
		{
			name:       "[Unit] GetContent: Detached overrides attached",
			signedData: sdAttached,
			config: &VerifyConfig{
				Data: detachedContent,
			},
			expectedContent: detachedContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getContent(tt.signedData, tt.config)
			if string(result) != string(tt.expectedContent) {
				t.Errorf("Content mismatch: expected %q, got %q", tt.expectedContent, result)
			}
		})
	}
}

// TestU_ParseCertificates tests the parseCertificates function.
func TestU_ParseCertificates(t *testing.T) {
	// Generate a test certificate
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	tests := []struct {
		name        string
		raw         []byte
		expectError bool
		expectCount int
	}{
		{
			name:        "[Unit] ParseCertificates: Valid single cert",
			raw:         cert.Raw,
			expectError: false,
			expectCount: 1,
		},
		{
			name:        "[Unit] ParseCertificates: Empty data",
			raw:         []byte{},
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "[Unit] ParseCertificates: Invalid data",
			raw:         []byte{0xFF, 0xFF, 0xFF},
			expectError: true,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificates(tt.raw)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(certs) != tt.expectCount {
					t.Errorf("Certificate count mismatch: expected %d, got %d", tt.expectCount, len(certs))
				}
			}
		})
	}
}

// =============================================================================
// Unit Tests: RFC 9882 Digest Security Level Warnings
// =============================================================================

// TestU_CheckDigestSecurityLevel_RFC9882 tests the checkDigestSecurityLevel function.
func TestU_CheckDigestSecurityLevel_RFC9882(t *testing.T) {
	tests := []struct {
		name          string
		sigAlgOID     asn1.ObjectIdentifier
		digestAlg     crypto.Hash
		expectWarning bool
	}{
		// ML-DSA-87 (Level 5) - requires SHA-512
		{
			name:          "[Unit] RFC9882: ML-DSA-87 + SHA-512 = OK",
			sigAlgOID:     OIDMLDSA87,
			digestAlg:     crypto.SHA512,
			expectWarning: false,
		},
		{
			name:          "[Unit] RFC9882: ML-DSA-87 + SHA-384 = Warning",
			sigAlgOID:     OIDMLDSA87,
			digestAlg:     crypto.SHA384,
			expectWarning: true,
		},
		{
			name:          "[Unit] RFC9882: ML-DSA-87 + SHA-256 = Warning",
			sigAlgOID:     OIDMLDSA87,
			digestAlg:     crypto.SHA256,
			expectWarning: true,
		},
		// ML-DSA-65 (Level 3) - requires SHA-384 or SHA-512
		{
			name:          "[Unit] RFC9882: ML-DSA-65 + SHA-512 = OK",
			sigAlgOID:     OIDMLDSA65,
			digestAlg:     crypto.SHA512,
			expectWarning: false,
		},
		{
			name:          "[Unit] RFC9882: ML-DSA-65 + SHA-384 = OK",
			sigAlgOID:     OIDMLDSA65,
			digestAlg:     crypto.SHA384,
			expectWarning: false,
		},
		{
			name:          "[Unit] RFC9882: ML-DSA-65 + SHA-256 = Warning",
			sigAlgOID:     OIDMLDSA65,
			digestAlg:     crypto.SHA256,
			expectWarning: true,
		},
		// ML-DSA-44 (Level 1) - SHA-256 is fine
		{
			name:          "[Unit] RFC9882: ML-DSA-44 + SHA-256 = OK",
			sigAlgOID:     OIDMLDSA44,
			digestAlg:     crypto.SHA256,
			expectWarning: false,
		},
		// Classical algorithms - no warning
		{
			name:          "[Unit] RFC9882: ECDSA + SHA-256 = OK (no warning)",
			sigAlgOID:     OIDECDSAWithSHA256,
			digestAlg:     crypto.SHA256,
			expectWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := checkDigestSecurityLevel(tt.sigAlgOID, tt.digestAlg)
			hasWarning := warning != ""
			if hasWarning != tt.expectWarning {
				if tt.expectWarning {
					t.Error("Expected warning but got none")
				} else {
					t.Errorf("Unexpected warning: %s", warning)
				}
			}
		})
	}
}

// TestF_Verify_RFC9882_Warning tests that verification produces warnings for
// suboptimal digest/ML-DSA combinations.
func TestF_Verify_RFC9882_Warning(t *testing.T) {
	// Create ML-DSA-87 key and cert
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA87)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA87)

	content := []byte("RFC 9882 warning test")

	// Sign with ML-DSA-87 but force SHA-256 (suboptimal per RFC 9882)
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256, // Force SHA-256 (should trigger warning)
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify - should succeed but produce a warning
	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Check that a warning was produced
	if len(result.Warnings) == 0 {
		t.Error("Expected RFC 9882 warning for ML-DSA-87 + SHA-256, but got none")
	} else {
		t.Logf("Got expected warning: %s", result.Warnings[0])
	}
}

// TestF_Verify_RFC9882_NoWarning tests that verification produces no warnings
// for correct digest/ML-DSA combinations.
func TestF_Verify_RFC9882_NoWarning(t *testing.T) {
	// Create ML-DSA-87 key and cert
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA87)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA87)

	content := []byte("RFC 9882 no warning test")

	// Sign with ML-DSA-87 and SHA-512 (correct per RFC 9882)
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA512, // Correct digest
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify - should succeed without warning
	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Check that no warning was produced
	if len(result.Warnings) > 0 {
		t.Errorf("Unexpected warning for ML-DSA-87 + SHA-512: %s", result.Warnings[0])
	}
}

// =============================================================================
// Unit Tests: RFC 9882 Warning Edge Cases
// =============================================================================

// TestU_CheckDigestSecurityLevel_MLDSA44_AllDigests tests ML-DSA-44 with all digests.
func TestU_CheckDigestSecurityLevel_MLDSA44_AllDigests(t *testing.T) {
	tests := []struct {
		name          string
		digestAlg     crypto.Hash
		expectWarning bool
	}{
		{"ML-DSA-44 + SHA-256 = OK", crypto.SHA256, false},
		{"ML-DSA-44 + SHA-384 = OK", crypto.SHA384, false},
		{"ML-DSA-44 + SHA-512 = OK", crypto.SHA512, false},
		{"ML-DSA-44 + SHA3-256 = OK", crypto.SHA3_256, false},
		{"ML-DSA-44 + SHA3-384 = OK", crypto.SHA3_384, false},
		{"ML-DSA-44 + SHA3-512 = OK", crypto.SHA3_512, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := checkDigestSecurityLevel(OIDMLDSA44, tt.digestAlg)
			hasWarning := warning != ""
			if hasWarning != tt.expectWarning {
				if tt.expectWarning {
					t.Error("Expected warning but got none")
				} else {
					t.Errorf("Unexpected warning: %s", warning)
				}
			}
		})
	}
}

// TestU_CheckDigestSecurityLevel_SLHDSA tests SLH-DSA OIDs (no warnings expected).
func TestU_CheckDigestSecurityLevel_SLHDSA(t *testing.T) {
	slhdsaOIDs := []asn1.ObjectIdentifier{
		OIDSLHDSA128s, OIDSLHDSA128f,
		OIDSLHDSA192s, OIDSLHDSA192f,
		OIDSLHDSA256s, OIDSLHDSA256f,
	}

	digests := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

	for _, oid := range slhdsaOIDs {
		for _, digest := range digests {
			t.Run(oid.String()+"_"+digest.String(), func(t *testing.T) {
				warning := checkDigestSecurityLevel(oid, digest)
				if warning != "" {
					t.Errorf("Unexpected warning for SLH-DSA: %s", warning)
				}
			})
		}
	}
}

// TestU_CheckDigestSecurityLevel_Classical tests classical algorithms (no warnings).
func TestU_CheckDigestSecurityLevel_Classical(t *testing.T) {
	classicalOIDs := []asn1.ObjectIdentifier{
		OIDECDSAWithSHA256, OIDECDSAWithSHA384, OIDECDSAWithSHA512,
		OIDSHA256WithRSA, OIDSHA384WithRSA, OIDSHA512WithRSA,
		OIDEd25519,
	}

	digests := []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}

	for _, oid := range classicalOIDs {
		for _, digest := range digests {
			t.Run(oid.String()+"_"+digest.String(), func(t *testing.T) {
				warning := checkDigestSecurityLevel(oid, digest)
				if warning != "" {
					t.Errorf("Unexpected warning for classical algorithm: %s", warning)
				}
			})
		}
	}
}

// TestU_CheckDigestSecurityLevel_WarningMessage tests the warning message content.
func TestU_CheckDigestSecurityLevel_WarningMessage(t *testing.T) {
	tests := []struct {
		name            string
		sigAlgOID       asn1.ObjectIdentifier
		digestAlg       crypto.Hash
		expectedContain string
	}{
		{
			name:            "ML-DSA-87 warning mentions SHA-512",
			sigAlgOID:       OIDMLDSA87,
			digestAlg:       crypto.SHA256,
			expectedContain: "SHA-512",
		},
		{
			name:            "ML-DSA-87 warning mentions Level 5",
			sigAlgOID:       OIDMLDSA87,
			digestAlg:       crypto.SHA256,
			expectedContain: "Level 5",
		},
		{
			name:            "ML-DSA-65 warning mentions SHA-384",
			sigAlgOID:       OIDMLDSA65,
			digestAlg:       crypto.SHA256,
			expectedContain: "SHA-384",
		},
		{
			name:            "ML-DSA-65 warning mentions Level 3",
			sigAlgOID:       OIDMLDSA65,
			digestAlg:       crypto.SHA256,
			expectedContain: "Level 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := checkDigestSecurityLevel(tt.sigAlgOID, tt.digestAlg)
			if warning == "" {
				t.Fatal("Expected warning but got none")
			}
			if !containsString(warning, tt.expectedContain) {
				t.Errorf("Warning should contain %q, got: %s", tt.expectedContain, warning)
			}
		})
	}
}

// containsString checks if str contains substr (case-insensitive would need strings.Contains).
func containsString(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || len(str) > len(substr) && findSubstring(str, substr))
}

func findSubstring(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// Functional Tests: RFC 9882 Warning Integration
// =============================================================================

// TestF_Verify_RFC9882_MLDSA65_Warning tests ML-DSA-65 with SHA-256 produces warning.
func TestF_Verify_RFC9882_MLDSA65_Warning(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	content := []byte("ML-DSA-65 warning test")

	// Sign with SHA-256 (suboptimal for Level 3)
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(result.Warnings) == 0 {
		t.Error("Expected RFC 9882 warning for ML-DSA-65 + SHA-256")
	}
}

// TestF_Verify_RFC9882_MLDSA65_NoWarning_SHA384 tests ML-DSA-65 with SHA-384 produces no warning.
func TestF_Verify_RFC9882_MLDSA65_NoWarning_SHA384(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA65)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA65)

	content := []byte("ML-DSA-65 no warning test")

	// Sign with SHA-384 (correct for Level 3)
	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(result.Warnings) > 0 {
		t.Errorf("Unexpected warning for ML-DSA-65 + SHA-384: %s", result.Warnings[0])
	}
}

// TestF_Verify_RFC9882_MLDSA44_NoWarning tests ML-DSA-44 with SHA-256 produces no warning.
func TestF_Verify_RFC9882_MLDSA44_NoWarning(t *testing.T) {
	kp := generateMLDSAKeyPair(t, pkicrypto.AlgMLDSA44)
	cert := generateMLDSACertificate(t, kp, pkicrypto.AlgMLDSA44)

	content := []byte("ML-DSA-44 test")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(result.Warnings) > 0 {
		t.Errorf("Unexpected warning for ML-DSA-44 + SHA-256: %s", result.Warnings[0])
	}
}

// TestF_Verify_RFC9882_SLHDSA_NoWarning tests SLH-DSA produces no warnings.
func TestF_Verify_RFC9882_SLHDSA_NoWarning(t *testing.T) {
	kp := generateSLHDSAKeyPair(t, pkicrypto.AlgSLHDSA128f)
	cert := generateSLHDSACertificate(t, kp, pkicrypto.AlgSLHDSA128f)

	content := []byte("SLH-DSA test")

	signedData, err := Sign(context.Background(), content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if len(result.Warnings) > 0 {
		t.Errorf("Unexpected warning for SLH-DSA: %s", result.Warnings[0])
	}
}

// TestF_Verify_Classical_NoWarning tests classical algorithms produce no warnings.
func TestF_Verify_Classical_NoWarning(t *testing.T) {
	tests := []struct {
		name      string
		keyGen    func(t *testing.T) *testKeyPair
		digestAlg crypto.Hash
	}{
		{"ECDSA P-256 + SHA-256", func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P256()) }, crypto.SHA256},
		{"ECDSA P-384 + SHA-384", func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P384()) }, crypto.SHA384},
		{"RSA + SHA-256", func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) }, crypto.SHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := tt.keyGen(t)
			cert := generateTestCertificate(t, kp)

			content := []byte("classical test")

			signedData, err := Sign(context.Background(), content, &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				DigestAlg:    tt.digestAlg,
				IncludeCerts: true,
			})
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			result, err := Verify(context.Background(), signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if len(result.Warnings) > 0 {
				t.Errorf("Unexpected warning for classical algorithm: %s", result.Warnings[0])
			}
		})
	}
}

// =============================================================================
// Unit Tests: OID to Hash Mapping (Additional Coverage)
// =============================================================================

// TestU_OidToHash_SHA3 tests SHA3 OID to hash mapping.
func TestU_OidToHash_SHA3(t *testing.T) {
	tests := []struct {
		name         string
		oid          asn1.ObjectIdentifier
		expectedHash crypto.Hash
	}{
		{"SHA3-256", OIDSHA3_256, crypto.SHA3_256},
		{"SHA3-384", OIDSHA3_384, crypto.SHA3_384},
		{"SHA3-512", OIDSHA3_512, crypto.SHA3_512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := oidToHash(tt.oid)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if hash != tt.expectedHash {
				t.Errorf("Hash mismatch: expected %v, got %v", tt.expectedHash, hash)
			}
		})
	}
}
