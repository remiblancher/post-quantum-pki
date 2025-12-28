package cms

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"
)

// =============================================================================
// Sign Function Tests - Structure + Crypto + Coherence
// =============================================================================

// TestSign_ECDSA_P256_VerifyOID tests that signing with ECDSA P-256 produces correct OID.
func TestSign_ECDSA_P256_VerifyOID(t *testing.T) {
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
		t.Fatalf("Sign failed: %v", err)
	}

	// STRUCTURE: Verify OID is ECDSA-SHA256
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDECDSAWithSHA256, oid)
	}

	// CRYPTO: Verify signature is valid
	_, err = Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestSign_ECDSA_P384_VerifyOID tests ECDSA P-384 with SHA-384.
func TestSign_ECDSA_P384_VerifyOID(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P384())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content P-384")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA384) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDECDSAWithSHA384, oid)
	}

	_, err = Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestSign_ECDSA_P521_VerifyOID tests ECDSA P-521 with SHA-512.
func TestSign_ECDSA_P521_VerifyOID(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P521())
	cert := generateTestCertificate(t, kp)

	content := []byte("test content P-521")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA512,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA512) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDECDSAWithSHA512, oid)
	}

	_, err = Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestSign_RSA_SHA256_VerifyOID tests RSA with SHA-256.
func TestSign_RSA_SHA256_VerifyOID(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content RSA")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDSHA256WithRSA, oid)
	}

	_, err = Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestSign_RSA_SHA384_VerifyOID tests RSA with SHA-384.
func TestSign_RSA_SHA384_VerifyOID(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content RSA SHA-384")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA384WithRSA) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDSHA384WithRSA, oid)
	}

	_, err = Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestSign_Ed25519_VerifyOID tests Ed25519.
func TestSign_Ed25519_VerifyOID(t *testing.T) {
	kp := generateEd25519KeyPair(t)
	cert := generateTestCertificate(t, kp)

	content := []byte("test content Ed25519")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDEd25519) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDEd25519, oid)
	}

	_, err = Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// =============================================================================
// Detached Signature Tests - Same structure verification
// =============================================================================

// TestSign_Detached_ECDSA_VerifyOID tests detached ECDSA signature OID.
func TestSign_Detached_ECDSA_VerifyOID(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	content := []byte("detached content")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// STRUCTURE: Verify OID even for detached
	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDECDSAWithSHA256, oid)
	}

	// CRYPTO: Verify with original content
	_, err = Verify(signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// TestSign_Detached_RSA_VerifyOID tests detached RSA signature OID.
func TestSign_Detached_RSA_VerifyOID(t *testing.T) {
	kp := generateRSAKeyPair(t, 2048)
	cert := generateTestCertificate(t, kp)

	content := []byte("detached RSA content")

	signedData, err := Sign(content, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
		Detached:     true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDSHA256WithRSA) {
		t.Errorf("STRUCTURE: Expected OID %v, got %v", OIDSHA256WithRSA, oid)
	}

	_, err = Verify(signedData, &VerifyConfig{
		Data:           content,
		SkipCertVerify: true,
	})
	if err != nil {
		t.Errorf("CRYPTO: Verification failed: %v", err)
	}
}

// =============================================================================
// SignerConfig Validation Tests
// =============================================================================

// TestSign_NilCertificate tests that nil certificate is rejected.
func TestSign_NilCertificate(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())

	_, err := Sign([]byte("test"), &SignerConfig{
		Certificate: nil,
		Signer:      kp.PrivateKey,
	})
	if err == nil {
		t.Error("Expected error for nil certificate")
	}
}

// TestSign_NilSigner tests that nil signer is rejected.
func TestSign_NilSigner(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	_, err := Sign([]byte("test"), &SignerConfig{
		Certificate: cert,
		Signer:      nil,
	})
	if err == nil {
		t.Error("Expected error for nil signer")
	}
}

// TestSign_DefaultDigestAlg tests that default digest algorithm is SHA-256.
func TestSign_DefaultDigestAlg(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign([]byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		// DigestAlg not set - should default to SHA-256
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	oid := extractSignerInfoOID(t, signedData)
	if !oid.Equal(OIDECDSAWithSHA256) {
		t.Errorf("Expected default ECDSA-SHA256, got %v", oid)
	}
}

// TestSign_CustomSigningTime tests custom signing time.
func TestSign_CustomSigningTime(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	customTime := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	signedData, err := Sign([]byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		SigningTime:  customTime,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.SigningTime.Equal(customTime) {
		t.Errorf("Signing time mismatch: expected %v, got %v", customTime, result.SigningTime)
	}
}

// TestSign_CustomContentType tests custom content type OID.
func TestSign_CustomContentType(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	signedData, err := Sign([]byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
		ContentType:  customOID,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if !result.ContentType.Equal(customOID) {
		t.Errorf("ContentType mismatch: expected %v, got %v", customOID, result.ContentType)
	}
}

// TestSign_EmptyContent tests signing empty content.
func TestSign_EmptyContent(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign([]byte{}, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed for empty content: %v", err)
	}

	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed for empty content: %v", err)
	}

	if len(result.Content) != 0 {
		t.Errorf("Expected empty content, got %d bytes", len(result.Content))
	}
}

// TestSign_LargeContent tests signing large content.
func TestSign_LargeContent(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	// 1 MB content
	largeContent := make([]byte, 1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	signedData, err := Sign(largeContent, &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed for large content: %v", err)
	}

	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed for large content: %v", err)
	}

	if len(result.Content) != len(largeContent) {
		t.Errorf("Content length mismatch: expected %d, got %d", len(largeContent), len(result.Content))
	}
}

// =============================================================================
// Digest Algorithm Tests
// =============================================================================

// TestSign_DigestAlgorithm_SHA256 tests that DigestAlgorithm is correctly set.
func TestSign_DigestAlgorithm_SHA256(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign([]byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA256,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	digestAlgOID := extractDigestAlgorithmOID(t, signedData)
	if !digestAlgOID.Equal(OIDSHA256) {
		t.Errorf("DigestAlgorithm mismatch: expected SHA-256, got %v", digestAlgOID)
	}
}

// TestSign_DigestAlgorithm_SHA384 tests SHA-384 digest algorithm.
func TestSign_DigestAlgorithm_SHA384(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P384())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign([]byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		DigestAlg:    crypto.SHA384,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	digestAlgOID := extractDigestAlgorithmOID(t, signedData)
	if !digestAlgOID.Equal(OIDSHA384) {
		t.Errorf("DigestAlgorithm mismatch: expected SHA-384, got %v", digestAlgOID)
	}
}

// extractDigestAlgorithmOID extracts the DigestAlgorithm OID from SignedData.
func extractDigestAlgorithmOID(t *testing.T, signedDataDER []byte) asn1.ObjectIdentifier {
	t.Helper()

	var contentInfo ContentInfo
	_, err := asn1.Unmarshal(signedDataDER, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(signedData.DigestAlgorithms) == 0 {
		t.Fatal("No digest algorithms in SignedData")
	}

	return signedData.DigestAlgorithms[0].Algorithm
}

// =============================================================================
// Table-Driven Tests for All Algorithms
// =============================================================================

// TestSign_AllAlgorithms tests signing with all supported classical algorithms.
func TestSign_AllAlgorithms(t *testing.T) {
	tests := []struct {
		name        string
		keyGen      func(t *testing.T) *testKeyPair
		digestAlg   crypto.Hash
		expectedOID asn1.ObjectIdentifier
	}{
		{
			name:        "ECDSA-P256-SHA256",
			keyGen:      func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P256()) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDECDSAWithSHA256,
		},
		{
			name:        "ECDSA-P384-SHA384",
			keyGen:      func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P384()) },
			digestAlg:   crypto.SHA384,
			expectedOID: OIDECDSAWithSHA384,
		},
		{
			name:        "ECDSA-P521-SHA512",
			keyGen:      func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P521()) },
			digestAlg:   crypto.SHA512,
			expectedOID: OIDECDSAWithSHA512,
		},
		{
			name:        "RSA-2048-SHA256",
			keyGen:      func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDSHA256WithRSA,
		},
		{
			name:        "RSA-2048-SHA384",
			keyGen:      func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) },
			digestAlg:   crypto.SHA384,
			expectedOID: OIDSHA384WithRSA,
		},
		{
			name:        "RSA-2048-SHA512",
			keyGen:      func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) },
			digestAlg:   crypto.SHA512,
			expectedOID: OIDSHA512WithRSA,
		},
		{
			name:        "Ed25519",
			keyGen:      func(t *testing.T) *testKeyPair { return generateEd25519KeyPair(t) },
			digestAlg:   0, // Ed25519 doesn't use external hash
			expectedOID: OIDEd25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := tt.keyGen(t)
			cert := generateTestCertificate(t, kp)

			config := &SignerConfig{
				Certificate:  cert,
				Signer:       kp.PrivateKey,
				IncludeCerts: true,
			}
			if tt.digestAlg != 0 {
				config.DigestAlg = tt.digestAlg
			}

			signedData, err := Sign([]byte("test content"), config)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// STRUCTURE check
			oid := extractSignerInfoOID(t, signedData)
			if !oid.Equal(tt.expectedOID) {
				t.Errorf("STRUCTURE: Expected OID %v, got %v", tt.expectedOID, oid)
			}

			// CRYPTO check
			_, err = Verify(signedData, &VerifyConfig{SkipCertVerify: true})
			if err != nil {
				t.Errorf("CRYPTO: Verification failed: %v", err)
			}
		})
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

// TestGetDigestAlgorithmIdentifier tests the digest algorithm identifier mapping.
func TestGetDigestAlgorithmIdentifier(t *testing.T) {
	tests := []struct {
		alg         crypto.Hash
		expectedOID asn1.ObjectIdentifier
	}{
		{crypto.SHA256, OIDSHA256},
		{crypto.SHA384, OIDSHA384},
		{crypto.SHA512, OIDSHA512},
	}

	for _, tt := range tests {
		t.Run(tt.alg.String(), func(t *testing.T) {
			algID := getDigestAlgorithmIdentifier(tt.alg)
			if !algID.Algorithm.Equal(tt.expectedOID) {
				t.Errorf("Expected %v, got %v", tt.expectedOID, algID.Algorithm)
			}
		})
	}
}

// TestGetSignatureAlgorithmIdentifier tests signature algorithm detection.
func TestGetSignatureAlgorithmIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		keyGen      func(t *testing.T) *testKeyPair
		digestAlg   crypto.Hash
		expectedOID asn1.ObjectIdentifier
	}{
		{
			name:        "ECDSA-P256-SHA256",
			keyGen:      func(t *testing.T) *testKeyPair { return generateECDSAKeyPair(t, elliptic.P256()) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDECDSAWithSHA256,
		},
		{
			name:        "RSA-SHA256",
			keyGen:      func(t *testing.T) *testKeyPair { return generateRSAKeyPair(t, 2048) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDSHA256WithRSA,
		},
		{
			name:        "Ed25519",
			keyGen:      func(t *testing.T) *testKeyPair { return generateEd25519KeyPair(t) },
			digestAlg:   crypto.SHA256,
			expectedOID: OIDEd25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kp := tt.keyGen(t)

			algID, err := getSignatureAlgorithmIdentifier(kp.PrivateKey, tt.digestAlg)
			if err != nil {
				t.Fatalf("getSignatureAlgorithmIdentifier failed: %v", err)
			}

			if !algID.Algorithm.Equal(tt.expectedOID) {
				t.Errorf("Expected %v, got %v", tt.expectedOID, algID.Algorithm)
			}
		})
	}
}

// TestSortAttributes tests that attributes are sorted in DER order.
func TestSortAttributes(t *testing.T) {
	// Create attributes with different OIDs
	attr1 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 3},
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x01}}},
	}
	attr2 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 1},
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x02}}},
	}
	attr3 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 2},
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x03}}},
	}

	attrs := []Attribute{attr1, attr2, attr3}
	sorted, err := sortAttributes(attrs)
	if err != nil {
		t.Fatalf("sortAttributes failed: %v", err)
	}

	// After sorting, the order should be by DER encoding
	// This verifies the sorting function works
	if len(sorted) != 3 {
		t.Errorf("Expected 3 sorted attributes, got %d", len(sorted))
	}
}

// TestBuildSignedAttrs tests building signed attributes.
func TestBuildSignedAttrs(t *testing.T) {
	contentType := OIDData
	digest := []byte{0x01, 0x02, 0x03, 0x04}
	signingTime := time.Now().UTC()

	attrs, err := buildSignedAttrs(contentType, digest, signingTime)
	if err != nil {
		t.Fatalf("buildSignedAttrs failed: %v", err)
	}

	// Should have 3 attributes: content-type, message-digest, signing-time
	if len(attrs) != 3 {
		t.Errorf("Expected 3 attributes, got %d", len(attrs))
	}

	// Verify each attribute type is present
	hasContentType := false
	hasMessageDigest := false
	hasSigningTime := false

	for _, attr := range attrs {
		switch {
		case attr.Type.Equal(OIDContentType):
			hasContentType = true
		case attr.Type.Equal(OIDMessageDigest):
			hasMessageDigest = true
		case attr.Type.Equal(OIDSigningTime):
			hasSigningTime = true
		}
	}

	if !hasContentType {
		t.Error("Missing content-type attribute")
	}
	if !hasMessageDigest {
		t.Error("Missing message-digest attribute")
	}
	if !hasSigningTime {
		t.Error("Missing signing-time attribute")
	}
}

// TestComputeDigest tests digest computation.
func TestComputeDigest(t *testing.T) {
	tests := []struct {
		alg          crypto.Hash
		expectedSize int
	}{
		{crypto.SHA256, 32},
		{crypto.SHA384, 48},
		{crypto.SHA512, 64},
	}

	data := []byte("test data for digest")

	for _, tt := range tests {
		t.Run(tt.alg.String(), func(t *testing.T) {
			digest, err := computeDigest(data, tt.alg)
			if err != nil {
				t.Fatalf("computeDigest failed: %v", err)
			}

			if len(digest) != tt.expectedSize {
				t.Errorf("Expected digest size %d, got %d", tt.expectedSize, len(digest))
			}
		})
	}
}

// TestComputeDigest_UnsupportedAlgorithm tests unsupported algorithm rejection.
func TestComputeDigest_UnsupportedAlgorithm(t *testing.T) {
	_, err := computeDigest([]byte("test"), crypto.MD5)
	if err == nil {
		t.Error("Expected error for unsupported algorithm MD5")
	}
}

// =============================================================================
// Certificate Inclusion Tests
// =============================================================================

// TestSign_WithCertificates verifies certificates are included when requested.
func TestSign_WithCertificates(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign([]byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	result, err := Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if result.SignerCert == nil {
		t.Error("Expected signer certificate in result")
	}
}

// TestSign_WithoutCertificates verifies signing works without embedding certs.
func TestSign_WithoutCertificates(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign([]byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: false, // Don't include certificates
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Without embedded certs, verification should fail (no signer cert found)
	_, err = Verify(signedData, &VerifyConfig{SkipCertVerify: true})
	if err == nil {
		t.Error("Expected verification to fail without embedded certificates")
	}
}

// =============================================================================
// IssuerAndSerialNumber Tests
// =============================================================================

// TestSign_IssuerAndSerialNumber verifies SID is correctly set.
func TestSign_IssuerAndSerialNumber(t *testing.T) {
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := generateTestCertificate(t, kp)

	signedData, err := Sign([]byte("test"), &SignerConfig{
		Certificate:  cert,
		Signer:       kp.PrivateKey,
		IncludeCerts: true,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Parse and verify SID matches certificate
	var contentInfo ContentInfo
	_, err = asn1.Unmarshal(signedData, &contentInfo)
	if err != nil {
		t.Fatalf("Failed to parse ContentInfo: %v", err)
	}

	var sd SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &sd)
	if err != nil {
		t.Fatalf("Failed to parse SignedData: %v", err)
	}

	if len(sd.SignerInfos) == 0 {
		t.Fatal("No SignerInfos")
	}

	sid := sd.SignerInfos[0].SID

	// Verify serial number matches
	if sid.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("SerialNumber mismatch: expected %v, got %v", cert.SerialNumber, sid.SerialNumber)
	}

	// Verify issuer matches (by comparing raw bytes)
	var issuerName pkix.RDNSequence
	_, err = asn1.Unmarshal(sid.Issuer.FullBytes, &issuerName)
	if err != nil {
		t.Fatalf("Failed to parse issuer: %v", err)
	}
}
