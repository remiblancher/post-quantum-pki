package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Credential Tests
// =============================================================================

func TestNewCredential(t *testing.T) {
	subject := Subject{
		CommonName:   "Test User",
		Organization: []string{"Test Org"},
	}

	cred := NewCredential("test-credential-001", subject, []string{"classic"})

	if cred.ID != "test-credential-001" {
		t.Errorf("expected ID 'test-credential-001', got '%s'", cred.ID)
	}
	if cred.Subject.CommonName != "Test User" {
		t.Errorf("expected CommonName 'Test User', got '%s'", cred.Subject.CommonName)
	}
	if len(cred.Profiles) != 1 || cred.Profiles[0] != "classic" {
		t.Errorf("expected Profiles ['classic'], got '%v'", cred.Profiles)
	}
	if cred.Status != StatusPending {
		t.Errorf("expected Status StatusPending, got '%s'", cred.Status)
	}
	if cred.Created.IsZero() {
		t.Error("Created should not be zero")
	}
	if len(cred.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(cred.Certificates))
	}
}

func TestCredential_AddCertificate(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	ref := CertificateRef{
		Serial:      "0x01",
		Role:        RoleSignature,
		Algorithm:   "ECDSA-SHA256",
		Fingerprint: "ABC123",
	}

	cred.AddCertificate(ref)

	if len(cred.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cred.Certificates))
	}
	if cred.Certificates[0].Serial != "0x01" {
		t.Errorf("expected serial '0x01', got '%s'", cred.Certificates[0].Serial)
	}
}

func TestCredential_SetValidity(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	cred.SetValidity(notBefore, notAfter)

	if !cred.NotBefore.Equal(notBefore) {
		t.Errorf("NotBefore mismatch")
	}
	if !cred.NotAfter.Equal(notAfter) {
		t.Errorf("NotAfter mismatch")
	}
}

func TestCredential_Activate(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	if cred.Status != StatusPending {
		t.Errorf("expected StatusPending before Activate")
	}

	cred.Activate()

	if cred.Status != StatusValid {
		t.Errorf("expected StatusValid after Activate, got '%s'", cred.Status)
	}
}

func TestCredential_Revoke(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})
	cred.Activate()

	cred.Revoke("keyCompromise")

	if cred.Status != StatusRevoked {
		t.Errorf("expected StatusRevoked, got '%s'", cred.Status)
	}
	if cred.RevokedAt == nil {
		t.Error("RevokedAt should not be nil")
	}
	if cred.RevocationReason != "keyCompromise" {
		t.Errorf("expected reason 'keyCompromise', got '%s'", cred.RevocationReason)
	}
}

func TestCredential_IsValid(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	// Not valid before Activate
	if cred.IsValid() {
		t.Error("should not be valid before Activate")
	}

	// Activate and set validity
	cred.Activate()
	cred.SetValidity(time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))

	if !cred.IsValid() {
		t.Error("should be valid after Activate with current validity")
	}

	// Test with future validity
	cred.SetValidity(time.Now().Add(1*time.Hour), time.Now().Add(2*time.Hour))
	if cred.IsValid() {
		t.Error("should not be valid when NotBefore is in the future")
	}
}

func TestCredential_IsExpired(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	// Set past validity
	cred.SetValidity(time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour))

	if !cred.IsExpired() {
		t.Error("should be expired when NotAfter is in the past")
	}

	// Set future validity
	cred.SetValidity(time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))

	if cred.IsExpired() {
		t.Error("should not be expired when NotAfter is in the future")
	}
}

func TestCredential_ContainsCertificate(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	cred.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})
	cred.AddCertificate(CertificateRef{Serial: "0x02", Role: RoleEncryption})

	if !cred.ContainsCertificate("0x01") {
		t.Error("should contain certificate 0x01")
	}
	if !cred.ContainsCertificate("0x02") {
		t.Error("should contain certificate 0x02")
	}
	if cred.ContainsCertificate("0x03") {
		t.Error("should not contain certificate 0x03")
	}
}

func TestCredential_GetCertificateByRole(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	cred.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})
	cred.AddCertificate(CertificateRef{Serial: "0x02", Role: RoleEncryption})

	sigRef := cred.GetCertificateByRole(RoleSignature)
	if sigRef == nil {
		t.Fatal("expected to find signature certificate")
	}
	if sigRef.Serial != "0x01" {
		t.Errorf("expected serial '0x01', got '%s'", sigRef.Serial)
	}

	encRef := cred.GetCertificateByRole(RoleEncryption)
	if encRef == nil {
		t.Fatal("expected to find encryption certificate")
	}
	if encRef.Serial != "0x02" {
		t.Errorf("expected serial '0x02', got '%s'", encRef.Serial)
	}

	unknownRef := cred.GetCertificateByRole(RoleSignaturePQC)
	if unknownRef != nil {
		t.Error("should not find non-existent role")
	}
}

func TestCredential_SignatureCertificates(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	cred.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})
	cred.AddCertificate(CertificateRef{Serial: "0x02", Role: RoleSignatureClassical})
	cred.AddCertificate(CertificateRef{Serial: "0x03", Role: RoleSignaturePQC})
	cred.AddCertificate(CertificateRef{Serial: "0x04", Role: RoleEncryption})

	sigCerts := cred.SignatureCertificates()

	if len(sigCerts) != 3 {
		t.Errorf("expected 3 signature certificates, got %d", len(sigCerts))
	}
}

func TestCredential_EncryptionCertificates(t *testing.T) {
	cred := NewCredential("test", Subject{CommonName: "Test"}, []string{"classic"})

	cred.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})
	cred.AddCertificate(CertificateRef{Serial: "0x02", Role: RoleEncryption})
	cred.AddCertificate(CertificateRef{Serial: "0x03", Role: RoleEncryptionClassical})
	cred.AddCertificate(CertificateRef{Serial: "0x04", Role: RoleEncryptionPQC})

	encCerts := cred.EncryptionCertificates()

	if len(encCerts) != 3 {
		t.Errorf("expected 3 encryption certificates, got %d", len(encCerts))
	}
}

func TestSubject_ToPkixName(t *testing.T) {
	s := Subject{
		CommonName:   "Test User",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
		Province:     []string{"CA"},
		Locality:     []string{"San Francisco"},
	}

	name := s.ToPkixName()

	if name.CommonName != "Test User" {
		t.Errorf("expected CommonName 'Test User', got '%s'", name.CommonName)
	}
	if len(name.Organization) != 1 || name.Organization[0] != "Test Org" {
		t.Errorf("unexpected Organization: %v", name.Organization)
	}
}

func TestSubjectFromPkixName(t *testing.T) {
	name := pkix.Name{
		CommonName:   "Test User",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
	}

	s := SubjectFromPkixName(name)

	if s.CommonName != "Test User" {
		t.Errorf("expected CommonName 'Test User', got '%s'", s.CommonName)
	}
	if len(s.Organization) != 1 || s.Organization[0] != "Test Org" {
		t.Errorf("unexpected Organization: %v", s.Organization)
	}
}

func TestCredential_JSONMarshalUnmarshal(t *testing.T) {
	original := NewCredential("test-json", Subject{
		CommonName:   "JSON Test",
		Organization: []string{"Test Org"},
	}, []string{"hybrid-catalyst"})

	original.Activate()
	original.SetValidity(time.Now(), time.Now().Add(365*24*time.Hour))
	original.AddCertificate(CertificateRef{
		Serial:       "0x01",
		Role:         RoleSignature,
		Algorithm:    "ECDSA-SHA256",
		AltAlgorithm: "ML-DSA-65",
		IsCatalyst:   true,
		Fingerprint:  "ABC123",
	})

	// Marshal
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Unmarshal
	var loaded Credential
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Compare
	if loaded.ID != original.ID {
		t.Errorf("ID mismatch: %s vs %s", loaded.ID, original.ID)
	}
	if loaded.Subject.CommonName != original.Subject.CommonName {
		t.Errorf("Subject mismatch")
	}
	if len(loaded.Profiles) != len(original.Profiles) {
		t.Errorf("Profiles length mismatch")
	}
	if len(loaded.Profiles) > 0 && loaded.Profiles[0] != original.Profiles[0] {
		t.Errorf("Profiles mismatch")
	}
	if loaded.Status != original.Status {
		t.Errorf("Status mismatch")
	}
	if len(loaded.Certificates) != len(original.Certificates) {
		t.Errorf("Certificates count mismatch")
	}
	if loaded.Certificates[0].IsCatalyst != original.Certificates[0].IsCatalyst {
		t.Errorf("IsCatalyst mismatch")
	}
}

func TestCredential_Summary(t *testing.T) {
	cred := NewCredential("test-summary", Subject{CommonName: "Summary Test"}, []string{"classic"})
	cred.Activate()
	cred.SetValidity(time.Now(), time.Now().Add(365*24*time.Hour))
	cred.AddCertificate(CertificateRef{Serial: "0x01", Role: RoleSignature})

	summary := cred.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}
	if !contains(summary, "test-summary") {
		t.Error("Summary should contain credential ID")
	}
	if !contains(summary, "Summary Test") {
		t.Error("Summary should contain subject")
	}
}

// =============================================================================
// PEM Tests
// =============================================================================

func TestEncodeCertificatesPEM(t *testing.T) {
	cert := generateTestCertificate(t)

	pem, err := EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	if len(pem) == 0 {
		t.Error("PEM should not be empty")
	}
	if !contains(string(pem), "-----BEGIN CERTIFICATE-----") {
		t.Error("PEM should contain certificate header")
	}
}

func TestDecodeCertificatesPEM(t *testing.T) {
	cert := generateTestCertificate(t)

	// Encode
	pemData, err := EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Decode
	certs, err := DecodeCertificatesPEM(pemData)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("certificate subject mismatch")
	}
}

func TestEncodeCertificatesPEM_Multiple(t *testing.T) {
	cert1 := generateTestCertificate(t)
	cert2 := generateTestCertificate(t)

	pemData, err := EncodeCertificatesPEM([]*x509.Certificate{cert1, cert2})
	if err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	certs, err := DecodeCertificatesPEM(pemData)
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("expected 2 certificates, got %d", len(certs))
	}
}

func TestDecodeCertificatesPEM_Empty(t *testing.T) {
	certs, err := DecodeCertificatesPEM([]byte{})
	if err != nil {
		t.Fatalf("unexpected error for empty data: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(certs))
	}
}

// =============================================================================
// FileStore Tests
// =============================================================================

func TestFileStore_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-save", Subject{CommonName: "Save Test"}, []string{"classic"})
	cred.Activate()
	cred.SetValidity(time.Now(), time.Now().Add(365*24*time.Hour))

	// Generate test certificate
	cert := generateTestCertificate(t)
	cred.AddCertificate(CertificateRef{
		Serial:      "0x01",
		Role:        RoleSignature,
		Algorithm:   cert.SignatureAlgorithm.String(),
		Fingerprint: "TEST",
	})

	// Save
	if err := store.Save(cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load
	loaded, err := store.Load("test-save")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.ID != cred.ID {
		t.Errorf("ID mismatch: %s vs %s", loaded.ID, cred.ID)
	}
	if loaded.Subject.CommonName != cred.Subject.CommonName {
		t.Errorf("Subject mismatch")
	}
}

func TestFileStore_LoadCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-certs", Subject{CommonName: "Certs Test"}, []string{"classic"})
	cert := generateTestCertificate(t)

	if err := store.Save(cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	certs, err := store.LoadCertificates("test-certs")
	if err != nil {
		t.Fatalf("LoadCertificates failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestFileStore_ListAll(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create multiple credentials
	for i := 1; i <= 3; i++ {
		cred := NewCredential(
			"credential-"+string(rune('a'+i-1)),
			Subject{CommonName: "Test"},
			[]string{"classic"},
		)
		if err := store.Save(cred, nil, nil, nil); err != nil {
			t.Fatalf("Save failed: %v", err)
		}
	}

	credentials, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(credentials) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(credentials))
	}
}

func TestFileStore_List(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	// Create credentials with different subjects
	cred1 := NewCredential("credential-alice", Subject{CommonName: "Alice"}, []string{"classic"})
	cred2 := NewCredential("credential-bob", Subject{CommonName: "Bob"}, []string{"classic"})
	cred3 := NewCredential("credential-alice2", Subject{CommonName: "Alice Smith"}, []string{"classic"})

	_ = store.Save(cred1, nil, nil, nil)
	_ = store.Save(cred2, nil, nil, nil)
	_ = store.Save(cred3, nil, nil, nil)

	// List with filter
	ids, err := store.List("Alice")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(ids) != 2 {
		t.Errorf("expected 2 credentials matching 'Alice', got %d", len(ids))
	}

	// List all
	allIds, err := store.List("")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(allIds) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(allIds))
	}
}

func TestFileStore_UpdateStatus(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-status", Subject{CommonName: "Status Test"}, []string{"classic"})
	cred.Activate()

	if err := store.Save(cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Update status
	if err := store.UpdateStatus("test-status", StatusRevoked, "keyCompromise"); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	// Reload and verify
	loaded, err := store.Load("test-status")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Status != StatusRevoked {
		t.Errorf("expected StatusRevoked, got '%s'", loaded.Status)
	}
	if loaded.RevocationReason != "keyCompromise" {
		t.Errorf("expected reason 'keyCompromise', got '%s'", loaded.RevocationReason)
	}
}

func TestFileStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	cred := NewCredential("test-delete", Subject{CommonName: "Delete Test"}, []string{"classic"})

	if err := store.Save(cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	if !store.Exists("test-delete") {
		t.Error("credential should exist after save")
	}

	if err := store.Delete("test-delete"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if store.Exists("test-delete") {
		t.Error("credential should not exist after delete")
	}
}

func TestFileStore_Exists(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	if store.Exists("nonexistent") {
		t.Error("should return false for nonexistent credential")
	}

	cred := NewCredential("test-exists", Subject{CommonName: "Exists Test"}, []string{"classic"})
	_ = store.Save(cred, nil, nil, nil)

	if !store.Exists("test-exists") {
		t.Error("should return true for existing credential")
	}
}

func TestFileStore_Load_NotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	_, err := store.Load("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent credential")
	}
}

func TestFileStore_BasePath(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	expected := filepath.Join(tmpDir, "credentials")
	if store.BasePath() != expected {
		t.Errorf("expected basePath '%s', got '%s'", expected, store.BasePath())
	}
}

func TestFileStore_Init(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	credentialsDir := filepath.Join(tmpDir, "credentials")

	// Directory shouldn't exist yet
	if _, err := os.Stat(credentialsDir); !os.IsNotExist(err) {
		t.Error("credentials directory should not exist before Init")
	}

	if err := store.Init(); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Directory should exist now
	if _, err := os.Stat(credentialsDir); err != nil {
		t.Error("credentials directory should exist after Init")
	}
}

func TestFileStore_ListAll_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	credentials, err := store.ListAll()
	if err != nil {
		t.Fatalf("ListAll failed: %v", err)
	}

	if len(credentials) != 0 {
		t.Errorf("expected 0 credentials for empty directory, got %d", len(credentials))
	}
}

// =============================================================================
// CertificateRef Tests
// =============================================================================

func TestCertificateRefFromCert(t *testing.T) {
	cert := generateTestCertificate(t)

	ref := CertificateRefFromCert(cert, RoleSignature, true, "ML-DSA-65")

	if ref.Role != RoleSignature {
		t.Errorf("expected role RoleSignature, got '%s'", ref.Role)
	}
	if !ref.IsCatalyst {
		t.Error("expected IsCatalyst to be true")
	}
	if ref.AltAlgorithm != "ML-DSA-65" {
		t.Errorf("expected AltAlgorithm 'ML-DSA-65', got '%s'", ref.AltAlgorithm)
	}
	if ref.Serial == "" {
		t.Error("Serial should not be empty")
	}
}

// =============================================================================
// GenerateCredentialID Tests
// =============================================================================

func TestGenerateCredentialID(t *testing.T) {
	tests := []struct {
		name     string
		cn       string
		wantSlug string // Expected prefix (before date)
	}{
		{"simple name", "Alice", "alice"},
		{"with spaces", "Alice Smith", "alice-smith"},
		{"email style", "alice@example.com", "alice-example-com"},
		{"uppercase", "ALICE", "alice"},
		{"with numbers", "User123", "user123"},
		{"empty", "", "cred"},
		{"special chars", "User!@#$%^&*()", "user"},
		{"long name", "This Is A Very Long Common Name That Exceeds The Limit", "this-is-a-very-long-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := GenerateCredentialID(tt.cn)

			// Check format: {slug}-{YYYYMMDD}-{hash}
			parts := strings.Split(id, "-")
			if len(parts) < 3 {
				t.Errorf("expected at least 3 parts separated by '-', got %d: %s", len(parts), id)
				return
			}

			// Check slug prefix
			if !strings.HasPrefix(id, tt.wantSlug) {
				t.Errorf("expected ID to start with '%s', got '%s'", tt.wantSlug, id)
			}

			// Check date format (YYYYMMDD)
			dateIdx := len(parts) - 2
			if len(parts[dateIdx]) != 8 {
				t.Errorf("expected date part to be 8 chars, got %d: %s", len(parts[dateIdx]), parts[dateIdx])
			}

			// Check hash suffix
			hashIdx := len(parts) - 1
			if len(parts[hashIdx]) != 6 {
				t.Errorf("expected hash to be 6 chars, got %d: %s", len(parts[hashIdx]), parts[hashIdx])
			}
		})
	}
}

func TestGenerateCredentialID_Unique(t *testing.T) {
	// Generate multiple IDs and ensure they're unique
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := GenerateCredentialID("Test")
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

// =============================================================================
// Status Tests
// =============================================================================

func TestStatus_Constants(t *testing.T) {
	// Verify status constants exist and have expected values
	if StatusValid != "valid" {
		t.Errorf("unexpected StatusValid value: %s", StatusValid)
	}
	if StatusRevoked != "revoked" {
		t.Errorf("unexpected StatusRevoked value: %s", StatusRevoked)
	}
	if StatusExpired != "expired" {
		t.Errorf("unexpected StatusExpired value: %s", StatusExpired)
	}
	if StatusPending != "pending" {
		t.Errorf("unexpected StatusPending value: %s", StatusPending)
	}
}

// =============================================================================
// CertRole Tests
// =============================================================================

func TestCertRole_Constants(t *testing.T) {
	roles := []CertRole{
		RoleSignature,
		RoleSignatureClassical,
		RoleSignaturePQC,
		RoleEncryption,
		RoleEncryptionClassical,
		RoleEncryptionPQC,
	}

	for _, role := range roles {
		if role == "" {
			t.Error("role should not be empty")
		}
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func generateTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	// Generate key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
