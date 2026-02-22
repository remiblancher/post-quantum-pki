package pki

import (
	"encoding/asn1"
	"testing"
)

// =============================================================================
// AlgorithmName Tests
// =============================================================================

func TestU_AlgorithmName(t *testing.T) {
	tests := []struct {
		name      string
		oid       asn1.ObjectIdentifier
		wantEmpty bool
	}{
		{
			name:      "[Unit] AlgorithmName: RSA SHA-256",
			oid:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // sha256WithRSAEncryption
			wantEmpty: false,
		},
		{
			name:      "[Unit] AlgorithmName: ECDSA SHA-256",
			oid:       asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, // ecdsa-with-SHA256
			wantEmpty: false,
		},
		{
			name:      "[Unit] AlgorithmName: ECDSA SHA-384",
			oid:       asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, // ecdsa-with-SHA384
			wantEmpty: false,
		},
		{
			name:      "[Unit] AlgorithmName: unknown OID",
			oid:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9},
			wantEmpty: false, // Should return something, even if just the OID string
		},
		{
			name:      "[Unit] AlgorithmName: empty OID",
			oid:       asn1.ObjectIdentifier{},
			wantEmpty: true, // Empty OID may return empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AlgorithmName(tt.oid)
			if tt.wantEmpty && result != "" {
				t.Errorf("AlgorithmName() = %s, want empty", result)
			}
			if !tt.wantEmpty && result == "" {
				t.Error("AlgorithmName() returned empty string")
			}
		})
	}
}

// =============================================================================
// ExtractSignatureAlgorithmOID Tests
// =============================================================================

func TestU_ExtractSignatureAlgorithmOID(t *testing.T) {
	t.Run("[Unit] ExtractSignatureAlgorithmOID: invalid certificate", func(t *testing.T) {
		_, err := ExtractSignatureAlgorithmOID([]byte("not a valid certificate"))
		if err == nil {
			t.Error("ExtractSignatureAlgorithmOID() should fail for invalid certificate")
		}
	})

	t.Run("[Unit] ExtractSignatureAlgorithmOID: empty data", func(t *testing.T) {
		_, err := ExtractSignatureAlgorithmOID([]byte{})
		if err == nil {
			t.Error("ExtractSignatureAlgorithmOID() should fail for empty data")
		}
	})

	t.Run("[Unit] ExtractSignatureAlgorithmOID: nil data", func(t *testing.T) {
		_, err := ExtractSignatureAlgorithmOID(nil)
		if err == nil {
			t.Error("ExtractSignatureAlgorithmOID() should fail for nil data")
		}
	})

	t.Run("[Unit] ExtractSignatureAlgorithmOID: truncated data", func(t *testing.T) {
		// ASN.1 sequence start but truncated
		truncated := []byte{0x30, 0x82, 0x01}
		_, err := ExtractSignatureAlgorithmOID(truncated)
		if err == nil {
			t.Error("ExtractSignatureAlgorithmOID() should fail for truncated data")
		}
	})
}

// =============================================================================
// Common Algorithm OIDs Tests
// =============================================================================

func TestU_CommonAlgorithmOIDs(t *testing.T) {
	// Test that common algorithm OIDs return recognizable names
	commonOIDs := map[string]asn1.ObjectIdentifier{
		"RSA-SHA256":   {1, 2, 840, 113549, 1, 1, 11},
		"RSA-SHA384":   {1, 2, 840, 113549, 1, 1, 12},
		"RSA-SHA512":   {1, 2, 840, 113549, 1, 1, 13},
		"ECDSA-SHA256": {1, 2, 840, 10045, 4, 3, 2},
		"ECDSA-SHA384": {1, 2, 840, 10045, 4, 3, 3},
		"ECDSA-SHA512": {1, 2, 840, 10045, 4, 3, 4},
	}

	for algName, oid := range commonOIDs {
		t.Run("[Unit] CommonAlgorithmOIDs: "+algName, func(t *testing.T) {
			name := AlgorithmName(oid)
			if name == "" {
				t.Errorf("AlgorithmName(%v) returned empty for %s", oid, algName)
			}
		})
	}
}
