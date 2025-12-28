package ocsp

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// =============================================================================
// CertID Tests
// =============================================================================

// TestNewCertID_SHA256 tests CertID creation with SHA-256.
func TestNewCertID_SHA256(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	// Verify the CertID structure
	if !certID.HashAlgorithm.Algorithm.Equal(OIDSHA256) {
		t.Errorf("Expected SHA-256 OID, got %v", certID.HashAlgorithm.Algorithm)
	}

	if len(certID.IssuerNameHash) != 32 { // SHA-256 produces 32 bytes
		t.Errorf("Expected 32-byte issuer name hash, got %d bytes", len(certID.IssuerNameHash))
	}

	if len(certID.IssuerKeyHash) != 32 {
		t.Errorf("Expected 32-byte issuer key hash, got %d bytes", len(certID.IssuerKeyHash))
	}

	if certID.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("Serial number mismatch: expected %v, got %v", cert.SerialNumber, certID.SerialNumber)
	}
}

// TestNewCertID_SHA384 tests CertID creation with SHA-384.
func TestNewCertID_SHA384(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA384, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	if !certID.HashAlgorithm.Algorithm.Equal(OIDSHA384) {
		t.Errorf("Expected SHA-384 OID, got %v", certID.HashAlgorithm.Algorithm)
	}

	if len(certID.IssuerNameHash) != 48 { // SHA-384 produces 48 bytes
		t.Errorf("Expected 48-byte issuer name hash, got %d bytes", len(certID.IssuerNameHash))
	}
}

// TestNewCertID_SHA512 tests CertID creation with SHA-512.
func TestNewCertID_SHA512(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA512, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	if !certID.HashAlgorithm.Algorithm.Equal(OIDSHA512) {
		t.Errorf("Expected SHA-512 OID, got %v", certID.HashAlgorithm.Algorithm)
	}

	if len(certID.IssuerNameHash) != 64 { // SHA-512 produces 64 bytes
		t.Errorf("Expected 64-byte issuer name hash, got %d bytes", len(certID.IssuerNameHash))
	}
}

// TestNewCertID_SHA1 tests CertID creation with SHA-1 (legacy).
func TestNewCertID_SHA1(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA1, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	if !certID.HashAlgorithm.Algorithm.Equal(OIDSHA1) {
		t.Errorf("Expected SHA-1 OID, got %v", certID.HashAlgorithm.Algorithm)
	}

	if len(certID.IssuerNameHash) != 20 { // SHA-1 produces 20 bytes
		t.Errorf("Expected 20-byte issuer name hash, got %d bytes", len(certID.IssuerNameHash))
	}
}

// TestNewCertID_UnsupportedHash tests CertID creation with unsupported hash.
func TestNewCertID_UnsupportedHash(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	_, err := NewCertID(crypto.MD5, caCert, cert)
	if err == nil {
		t.Error("Expected error for unsupported hash algorithm")
	}
}

// TestCertID_MatchesCertID tests CertID matching.
func TestCertID_MatchesCertID(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	// Should match the same certificate
	if !certID.MatchesCertID(caCert, cert.SerialNumber) {
		t.Error("CertID should match the same certificate")
	}

	// Should not match different serial
	if certID.MatchesCertID(caCert, big.NewInt(999999)) {
		t.Error("CertID should not match different serial number")
	}
}

// TestCertID_MatchesIssuer tests issuer matching.
func TestCertID_MatchesIssuer(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	certID, err := NewCertID(crypto.SHA256, caCert, cert)
	if err != nil {
		t.Fatalf("NewCertID failed: %v", err)
	}

	// Should match the issuer
	if !certID.MatchesIssuer(caCert) {
		t.Error("CertID should match the issuer")
	}

	// Should not match different CA
	otherCA, _ := generateTestCA(t)
	if certID.MatchesIssuer(otherCA) {
		t.Error("CertID should not match different CA")
	}
}

// =============================================================================
// Request Creation Tests
// =============================================================================

// TestCreateRequest tests basic request creation.
func TestCreateRequest(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	req, err := CreateRequest(caCert, []*x509.Certificate{cert}, crypto.SHA256)
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	// Verify request structure
	if req.TBSRequest.Version != 0 {
		t.Errorf("Expected version 0, got %d", req.TBSRequest.Version)
	}

	if len(req.TBSRequest.RequestList) != 1 {
		t.Errorf("Expected 1 request, got %d", len(req.TBSRequest.RequestList))
	}
}

// TestCreateRequest_MultipleCertificates tests request with multiple certs.
func TestCreateRequest_MultipleCertificates(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())

	cert1 := issueTestCertificate(t, caCert, caKey, kp)
	cert2 := issueTestCertificate(t, caCert, caKey, kp)
	cert3 := issueTestCertificate(t, caCert, caKey, kp)

	req, err := CreateRequest(caCert, []*x509.Certificate{cert1, cert2, cert3}, crypto.SHA256)
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	if len(req.TBSRequest.RequestList) != 3 {
		t.Errorf("Expected 3 requests, got %d", len(req.TBSRequest.RequestList))
	}
}

// TestCreateRequest_NoCertificates tests request with no certificates.
func TestCreateRequest_NoCertificates(t *testing.T) {
	caCert, _ := generateTestCA(t)

	_, err := CreateRequest(caCert, []*x509.Certificate{}, crypto.SHA256)
	if err == nil {
		t.Error("Expected error for empty certificate list")
	}
}

// TestCreateRequestWithNonce tests request creation with nonce.
func TestCreateRequestWithNonce(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	nonce := []byte("test-nonce-12345")
	req, err := CreateRequestWithNonce(caCert, []*x509.Certificate{cert}, crypto.SHA256, nonce)
	if err != nil {
		t.Fatalf("CreateRequestWithNonce failed: %v", err)
	}

	// Verify nonce extension is present
	if len(req.TBSRequest.RequestExtensions) != 1 {
		t.Errorf("Expected 1 extension, got %d", len(req.TBSRequest.RequestExtensions))
	}

	// Extract and verify nonce
	extractedNonce := req.GetNonce()
	if !bytes.Equal(extractedNonce, nonce) {
		t.Errorf("Nonce mismatch: expected %x, got %x", nonce, extractedNonce)
	}
}

// =============================================================================
// Request Parsing Tests
// =============================================================================

// TestParseRequest_RoundTrip tests request marshal/parse round trip.
func TestParseRequest_RoundTrip(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	req, err := CreateRequest(caCert, []*x509.Certificate{cert}, crypto.SHA256)
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	// Marshal
	data, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Parse
	parsed, err := ParseRequest(data)
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	// Verify
	if len(parsed.TBSRequest.RequestList) != 1 {
		t.Errorf("Expected 1 request, got %d", len(parsed.TBSRequest.RequestList))
	}

	if parsed.TBSRequest.RequestList[0].ReqCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("Serial number mismatch after round trip")
	}
}

// TestParseRequest_WithNonce tests parsing request with nonce.
func TestParseRequest_WithNonce(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	nonce := []byte("my-test-nonce")
	req, err := CreateRequestWithNonce(caCert, []*x509.Certificate{cert}, crypto.SHA256, nonce)
	if err != nil {
		t.Fatalf("CreateRequestWithNonce failed: %v", err)
	}

	data, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	parsed, err := ParseRequest(data)
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	extractedNonce := parsed.GetNonce()
	if !bytes.Equal(extractedNonce, nonce) {
		t.Errorf("Nonce mismatch: expected %x, got %x", nonce, extractedNonce)
	}
}

// TestParseRequest_InvalidData tests parsing invalid data.
func TestParseRequest_InvalidData(t *testing.T) {
	_, err := ParseRequest([]byte("not a valid OCSP request"))
	if err == nil {
		t.Error("Expected error for invalid data")
	}
}

// TestParseRequest_TrailingData tests parsing request with trailing data.
func TestParseRequest_TrailingData(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	req, _ := CreateRequest(caCert, []*x509.Certificate{cert}, crypto.SHA256)
	data, _ := req.Marshal()

	// Add trailing data
	dataWithTrailing := append(data, []byte("trailing garbage")...)

	_, err := ParseRequest(dataWithTrailing)
	if err == nil {
		t.Error("Expected error for trailing data")
	}
}

// =============================================================================
// HTTP Parsing Tests
// =============================================================================

// TestParseRequestFromHTTP_POST tests POST request parsing.
func TestParseRequestFromHTTP_POST(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	req, _ := CreateRequest(caCert, []*x509.Certificate{cert}, crypto.SHA256)
	data, _ := req.Marshal()

	httpReq := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(data))
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	parsed, err := ParseRequestFromHTTP(httpReq)
	if err != nil {
		t.Fatalf("ParseRequestFromHTTP failed: %v", err)
	}

	if len(parsed.TBSRequest.RequestList) != 1 {
		t.Errorf("Expected 1 request, got %d", len(parsed.TBSRequest.RequestList))
	}
}

// TestParseRequestFromHTTP_GET tests GET request parsing.
func TestParseRequestFromHTTP_GET(t *testing.T) {
	caCert, caKey := generateTestCA(t)
	kp := generateECDSAKeyPair(t, elliptic.P256())
	cert := issueTestCertificate(t, caCert, caKey, kp)

	req, _ := CreateRequest(caCert, []*x509.Certificate{cert}, crypto.SHA256)
	data, _ := req.Marshal()

	// Base64 encode for GET
	encoded := base64.StdEncoding.EncodeToString(data)
	httpReq := httptest.NewRequest(http.MethodGet, "/"+encoded, nil)

	parsed, err := ParseRequestFromHTTP(httpReq)
	if err != nil {
		t.Fatalf("ParseRequestFromHTTP GET failed: %v", err)
	}

	if len(parsed.TBSRequest.RequestList) != 1 {
		t.Errorf("Expected 1 request, got %d", len(parsed.TBSRequest.RequestList))
	}
}

// TestParseRequestFromHTTP_UnsupportedMethod tests unsupported HTTP method.
func TestParseRequestFromHTTP_UnsupportedMethod(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodPut, "/ocsp", nil)

	_, err := ParseRequestFromHTTP(httpReq)
	if err == nil {
		t.Error("Expected error for unsupported method")
	}
}

// TestParseRequestFromHTTP_EmptyPOST tests empty POST body.
func TestParseRequestFromHTTP_EmptyPOST(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodPost, "/ocsp", strings.NewReader(""))
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	_, err := ParseRequestFromHTTP(httpReq)
	if err == nil {
		t.Error("Expected error for empty POST body")
	}
}

// TestParseRequestFromHTTP_EmptyGET tests empty GET path.
func TestParseRequestFromHTTP_EmptyGET(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := ParseRequestFromHTTP(httpReq)
	if err == nil {
		t.Error("Expected error for empty GET path")
	}
}

// TestParseRequestFromHTTP_InvalidBase64 tests invalid base64 in GET.
func TestParseRequestFromHTTP_InvalidBase64(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/!!!not-valid-base64!!!", nil)

	_, err := ParseRequestFromHTTP(httpReq)
	if err == nil {
		t.Error("Expected error for invalid base64")
	}
}

// =============================================================================
// OID Tests
// =============================================================================

// TestOID_Values tests that OIDs have correct values.
func TestOID_Values(t *testing.T) {
	tests := []struct {
		name     string
		oid      []int
		expected []int
	}{
		{"OCSP Basic", OIDOcspBasic, []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}},
		{"OCSP Nonce", OIDOcspNonce, []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}},
		{"SHA-256", OIDSHA256, []int{2, 16, 840, 1, 101, 3, 4, 2, 1}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.oid) != len(tc.expected) {
				t.Errorf("OID length mismatch: expected %d, got %d", len(tc.expected), len(tc.oid))
				return
			}
			for i, v := range tc.expected {
				if tc.oid[i] != v {
					t.Errorf("OID value mismatch at index %d: expected %d, got %d", i, v, tc.oid[i])
				}
			}
		})
	}
}
