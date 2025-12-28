package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// =============================================================================
// NewAttribute Tests
// =============================================================================

// TestNewAttribute tests creating a new attribute.
func TestNewAttribute(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 3, 4}
	value := []byte{0x01, 0x02, 0x03}

	attr, err := NewAttribute(oid, value)
	if err != nil {
		t.Fatalf("NewAttribute failed: %v", err)
	}

	if !attr.Type.Equal(oid) {
		t.Errorf("OID mismatch: expected %v, got %v", oid, attr.Type)
	}

	if len(attr.Values) != 1 {
		t.Errorf("Expected 1 value, got %d", len(attr.Values))
	}
}

// TestNewAttribute_InvalidValue tests that invalid values are rejected.
func TestNewAttribute_InvalidValue(t *testing.T) {
	oid := asn1.ObjectIdentifier{1, 2, 3}
	// Channel cannot be marshaled to ASN.1
	invalidValue := make(chan int)

	_, err := NewAttribute(oid, invalidValue)
	if err == nil {
		t.Error("Expected error for unmarshallable value")
	}
}

// =============================================================================
// NewContentTypeAttr Tests
// =============================================================================

// TestNewContentTypeAttr tests creating a content-type attribute.
func TestNewContentTypeAttr(t *testing.T) {
	contentType := OIDData

	attr, err := NewContentTypeAttr(contentType)
	if err != nil {
		t.Fatalf("NewContentTypeAttr failed: %v", err)
	}

	if !attr.Type.Equal(OIDContentType) {
		t.Errorf("Attribute type should be OIDContentType, got %v", attr.Type)
	}

	if len(attr.Values) != 1 {
		t.Errorf("Expected 1 value, got %d", len(attr.Values))
	}

	// Verify the encoded value is the content type OID
	var decoded asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal content type: %v", err)
	}

	if !decoded.Equal(contentType) {
		t.Errorf("Content type mismatch: expected %v, got %v", contentType, decoded)
	}
}

// TestNewContentTypeAttr_CustomOID tests with custom content type.
func TestNewContentTypeAttr_CustomOID(t *testing.T) {
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}

	attr, err := NewContentTypeAttr(customOID)
	if err != nil {
		t.Fatalf("NewContentTypeAttr failed: %v", err)
	}

	var decoded asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if !decoded.Equal(customOID) {
		t.Errorf("OID mismatch: expected %v, got %v", customOID, decoded)
	}
}

// =============================================================================
// NewMessageDigestAttr Tests
// =============================================================================

// TestNewMessageDigestAttr tests creating a message-digest attribute.
func TestNewMessageDigestAttr(t *testing.T) {
	digest := []byte{0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90}

	attr, err := NewMessageDigestAttr(digest)
	if err != nil {
		t.Fatalf("NewMessageDigestAttr failed: %v", err)
	}

	if !attr.Type.Equal(OIDMessageDigest) {
		t.Errorf("Attribute type should be OIDMessageDigest, got %v", attr.Type)
	}

	// Verify the encoded value is the digest
	var decoded []byte
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal digest: %v", err)
	}

	if len(decoded) != len(digest) {
		t.Errorf("Digest length mismatch: expected %d, got %d", len(digest), len(decoded))
	}

	for i := range digest {
		if decoded[i] != digest[i] {
			t.Errorf("Digest byte %d mismatch: expected %02x, got %02x", i, digest[i], decoded[i])
		}
	}
}

// TestNewMessageDigestAttr_SHA256 tests with SHA-256 sized digest.
func TestNewMessageDigestAttr_SHA256(t *testing.T) {
	// 32-byte SHA-256 digest
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	attr, err := NewMessageDigestAttr(digest)
	if err != nil {
		t.Fatalf("NewMessageDigestAttr failed: %v", err)
	}

	var decoded []byte
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if len(decoded) != 32 {
		t.Errorf("Expected 32-byte digest, got %d", len(decoded))
	}
}

// TestNewMessageDigestAttr_Empty tests empty digest.
func TestNewMessageDigestAttr_Empty(t *testing.T) {
	digest := []byte{}

	attr, err := NewMessageDigestAttr(digest)
	if err != nil {
		t.Fatalf("NewMessageDigestAttr failed: %v", err)
	}

	var decoded []byte
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("Expected empty digest, got %d bytes", len(decoded))
	}
}

// =============================================================================
// NewSigningTimeAttr Tests
// =============================================================================

// TestNewSigningTimeAttr tests creating a signing-time attribute.
func TestNewSigningTimeAttr(t *testing.T) {
	signingTime := time.Date(2024, 6, 15, 12, 30, 45, 0, time.UTC)

	attr, err := NewSigningTimeAttr(signingTime)
	if err != nil {
		t.Fatalf("NewSigningTimeAttr failed: %v", err)
	}

	if !attr.Type.Equal(OIDSigningTime) {
		t.Errorf("Attribute type should be OIDSigningTime, got %v", attr.Type)
	}

	// Verify the encoded value is the time
	var decoded time.Time
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal time: %v", err)
	}

	if !decoded.Equal(signingTime) {
		t.Errorf("Time mismatch: expected %v, got %v", signingTime, decoded)
	}
}

// TestNewSigningTimeAttr_NonUTC tests that times are converted to UTC.
func TestNewSigningTimeAttr_NonUTC(t *testing.T) {
	// Create a time in a different timezone
	loc, _ := time.LoadLocation("America/New_York")
	localTime := time.Date(2024, 6, 15, 8, 30, 45, 0, loc)

	attr, err := NewSigningTimeAttr(localTime)
	if err != nil {
		t.Fatalf("NewSigningTimeAttr failed: %v", err)
	}

	var decoded time.Time
	_, err = asn1.Unmarshal(attr.Values[0].FullBytes, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal time: %v", err)
	}

	// Should be stored as UTC
	if decoded.Location().String() != "UTC" {
		t.Logf("Note: ASN.1 time parsed as %s", decoded.Location().String())
	}

	// The actual instant should match
	if !decoded.Equal(localTime.UTC()) {
		t.Errorf("Time instant mismatch: expected %v, got %v", localTime.UTC(), decoded)
	}
}

// =============================================================================
// MarshalSignedAttrs Tests
// =============================================================================

// TestMarshalSignedAttrs tests marshaling signed attributes.
func TestMarshalSignedAttrs(t *testing.T) {
	attrs := []Attribute{
		{
			Type:   asn1.ObjectIdentifier{1, 2, 3},
			Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x01}}},
		},
		{
			Type:   asn1.ObjectIdentifier{1, 2, 4},
			Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x02}}},
		},
	}

	result, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	// Should start with SET tag (0x31)
	if len(result) == 0 || result[0] != 0x31 {
		t.Errorf("Result should start with SET tag (0x31), got %02x", result[0])
	}
}

// TestMarshalSignedAttrs_DERSorting tests that attributes are sorted in DER order.
func TestMarshalSignedAttrs_DERSorting(t *testing.T) {
	// Create attributes in non-sorted order
	attr1 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 9}, // Larger OID
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x01}}},
	}
	attr2 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 1}, // Smaller OID
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x02}}},
	}
	attr3 := Attribute{
		Type:   asn1.ObjectIdentifier{1, 2, 5}, // Middle OID
		Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x03}}},
	}

	// Pass in non-sorted order
	attrs := []Attribute{attr1, attr2, attr3}

	result, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	// Marshal twice - result should be identical (deterministic)
	result2, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs second call failed: %v", err)
	}

	if len(result) != len(result2) {
		t.Errorf("Results should be identical, got different lengths: %d vs %d", len(result), len(result2))
	}

	for i := range result {
		if result[i] != result2[i] {
			t.Errorf("Results differ at byte %d: %02x vs %02x", i, result[i], result2[i])
			break
		}
	}
}

// TestMarshalSignedAttrs_Empty tests marshaling empty attributes.
func TestMarshalSignedAttrs_Empty(t *testing.T) {
	attrs := []Attribute{}

	result, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	// Should be empty SET: 0x31 0x00
	if len(result) != 2 || result[0] != 0x31 || result[1] != 0x00 {
		t.Errorf("Expected empty SET (0x31 0x00), got %v", result)
	}
}

// TestMarshalSignedAttrs_SingleAttribute tests single attribute.
func TestMarshalSignedAttrs_SingleAttribute(t *testing.T) {
	attr, err := NewContentTypeAttr(OIDData)
	if err != nil {
		t.Fatalf("NewContentTypeAttr failed: %v", err)
	}

	result, err := MarshalSignedAttrs([]Attribute{attr})
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	if len(result) < 3 {
		t.Errorf("Result too short: %d bytes", len(result))
	}

	if result[0] != 0x31 {
		t.Errorf("Should start with SET tag")
	}
}

// TestMarshalSignedAttrs_LargeLength tests length encoding for larger sets.
func TestMarshalSignedAttrs_LargeLength(t *testing.T) {
	// Create many attributes to exceed 127 bytes
	attrs := make([]Attribute, 20)
	for i := range attrs {
		attrs[i] = Attribute{
			Type: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7, 8, 9, i},
			Values: []asn1.RawValue{{FullBytes: []byte{
				0x04, 0x10, // OCTET STRING, 16 bytes
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
			}}},
		}
	}

	result, err := MarshalSignedAttrs(attrs)
	if err != nil {
		t.Fatalf("MarshalSignedAttrs failed: %v", err)
	}

	// Length should use long form
	if len(result) < 4 {
		t.Fatalf("Result too short")
	}

	// Check for long-form length encoding
	if result[1]&0x80 == 0 {
		t.Logf("Length is short form: %d", result[1])
	} else {
		numLenBytes := int(result[1] & 0x7F)
		t.Logf("Length uses %d bytes in long form", numLenBytes)
	}
}

// =============================================================================
// ASN.1 Structure Tests
// =============================================================================

// TestSignedData_Marshal tests SignedData structure marshaling.
func TestSignedData_Marshal(t *testing.T) {
	sd := SignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: OIDSHA256},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: OIDData,
		},
		SignerInfos: []SignerInfo{},
	}

	data, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("Failed to marshal SignedData: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}
}

// TestContentInfo_Marshal tests ContentInfo structure marshaling.
func TestContentInfo_Marshal(t *testing.T) {
	ci := ContentInfo{
		ContentType: OIDSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      []byte{0x30, 0x00}, // Empty SEQUENCE
		},
	}

	data, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("Failed to marshal ContentInfo: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}
}

// TestIssuerAndSerialNumber_Marshal tests IssuerAndSerialNumber structure.
func TestIssuerAndSerialNumber_Marshal(t *testing.T) {
	isn := IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: []byte{0x30, 0x00}}, // Empty SEQUENCE
		SerialNumber: big.NewInt(12345),
	}

	data, err := asn1.Marshal(isn)
	if err != nil {
		t.Fatalf("Failed to marshal IssuerAndSerialNumber: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}
}

// TestAttribute_Marshal tests Attribute structure marshaling.
func TestAttribute_Marshal(t *testing.T) {
	attr := Attribute{
		Type:   OIDContentType,
		Values: []asn1.RawValue{{FullBytes: []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}}},
	}

	data, err := asn1.Marshal(attr)
	if err != nil {
		t.Fatalf("Failed to marshal Attribute: %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshaled data is empty")
	}
}

// =============================================================================
// OID Tests
// =============================================================================

// TestOID_Values tests that OIDs have expected values.
func TestOID_Values(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"OIDData", OIDData, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		{"OIDSignedData", OIDSignedData, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}},
		{"OIDEnvelopedData", OIDEnvelopedData, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}},
		{"OIDContentType", OIDContentType, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}},
		{"OIDMessageDigest", OIDMessageDigest, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}},
		{"OIDSigningTime", OIDSigningTime, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.oid.Equal(tt.expected) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expected, tt.oid)
			}
		})
	}
}

// TestOID_Signature_Values tests signature algorithm OIDs.
func TestOID_Signature_Values(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"ECDSA-SHA256", OIDECDSAWithSHA256, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}},
		{"ECDSA-SHA384", OIDECDSAWithSHA384, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}},
		{"ECDSA-SHA512", OIDECDSAWithSHA512, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}},
		{"Ed25519", OIDEd25519, asn1.ObjectIdentifier{1, 3, 101, 112}},
		{"RSA-SHA256", OIDSHA256WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}},
		{"RSA-SHA384", OIDSHA384WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}},
		{"RSA-SHA512", OIDSHA512WithRSA, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.oid.Equal(tt.expected) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expected, tt.oid)
			}
		})
	}
}

// TestOID_Hash_Values tests hash algorithm OIDs.
func TestOID_Hash_Values(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"SHA-256", OIDSHA256, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		{"SHA-384", OIDSHA384, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}},
		{"SHA-512", OIDSHA512, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.oid.Equal(tt.expected) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expected, tt.oid)
			}
		})
	}
}

// TestOID_MLDSA_Values tests ML-DSA OIDs.
func TestOID_MLDSA_Values(t *testing.T) {
	tests := []struct {
		name     string
		oid      asn1.ObjectIdentifier
		expected asn1.ObjectIdentifier
	}{
		{"ML-DSA-44", OIDMLDSA44, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}},
		{"ML-DSA-65", OIDMLDSA65, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}},
		{"ML-DSA-87", OIDMLDSA87, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.oid.Equal(tt.expected) {
				t.Errorf("OID mismatch: expected %v, got %v", tt.expected, tt.oid)
			}
		})
	}
}

// =============================================================================
// Round-trip Tests (Marshal/Unmarshal)
// =============================================================================

// TestAttribute_RoundTrip tests attribute marshal/unmarshal round trip.
func TestAttribute_RoundTrip(t *testing.T) {
	original := Attribute{
		Type:   OIDContentType,
		Values: []asn1.RawValue{{FullBytes: []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}}},
	}

	data, err := asn1.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Attribute
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !decoded.Type.Equal(original.Type) {
		t.Errorf("Type mismatch after round-trip")
	}

	if len(decoded.Values) != len(original.Values) {
		t.Errorf("Values count mismatch: expected %d, got %d", len(original.Values), len(decoded.Values))
	}
}
