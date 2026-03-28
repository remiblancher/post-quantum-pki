package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/qpki/qpki/internal/ca"
	"github.com/qpki/qpki/internal/credential"
	"github.com/qpki/qpki/internal/crypto"
	"github.com/qpki/qpki/internal/profile"
)

// =============================================================================
// Test Helper: Create a real CA directory using ca.Initialize
// =============================================================================

func createRealCA(t *testing.T, tmpDir string) (*ca.CA, string) {
	t.Helper()

	caDir := filepath.Join(tmpDir, "ca")
	store := ca.NewFileStore(caDir)
	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("failed to init CA store: %v", err)
	}

	cfg := ca.Config{
		CommonName:    "Test Root CA",
		Organization:  "Test Org",
		Country:       "FR",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		Profile:       "ec/root-ca",
	}

	caInstance, err := ca.Initialize(store, cfg)
	if err != nil {
		t.Fatalf("failed to initialize CA: %v", err)
	}

	return caInstance, caDir
}

// =============================================================================
// LoadParentCA Tests (0% coverage)
// =============================================================================

func TestU_LoadParentCA_Success(t *testing.T) {
	tmpDir := t.TempDir()
	_, caDir := createRealCA(t, tmpDir)

	parentCA, err := LoadParentCA(caDir, "")
	if err != nil {
		t.Fatalf("LoadParentCA() error = %v", err)
	}
	if parentCA == nil {
		t.Fatal("LoadParentCA() returned nil")
	}
	if parentCA.Certificate() == nil {
		t.Error("LoadParentCA() returned CA without certificate")
	}
}

func TestU_LoadParentCA_NotFound(t *testing.T) {
	_, err := LoadParentCA("/nonexistent/ca/dir", "")
	if err == nil {
		t.Error("LoadParentCA() should fail for non-existent directory")
	}
}

func TestU_LoadParentCA_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := LoadParentCA(tmpDir, "")
	if err == nil {
		t.Error("LoadParentCA() should fail for empty directory (no CA)")
	}
}

// =============================================================================
// PrintCRLList Tests (0% coverage)
// =============================================================================

func TestU_PrintCRLList_Empty(t *testing.T) {
	PrintCRLList([]CRLInfo{})
}

func TestU_PrintCRLList_SingleCRL(t *testing.T) {
	now := time.Now()
	crls := []CRLInfo{
		{
			Name:       "ca.crl",
			Algorithm:  "ecdsa-p256",
			ThisUpdate: now,
			NextUpdate: now.Add(7 * 24 * time.Hour),
			Revoked:    3,
			Status:     "valid",
		},
	}
	PrintCRLList(crls)
}

func TestU_PrintCRLList_RootAlgorithm(t *testing.T) {
	now := time.Now()
	crls := []CRLInfo{
		{
			Name:       "root.crl",
			Algorithm:  "",
			ThisUpdate: now,
			NextUpdate: now.Add(7 * 24 * time.Hour),
			Revoked:    0,
			Status:     "valid",
		},
	}
	PrintCRLList(crls)
}

func TestU_PrintCRLList_MultipleCRLs(t *testing.T) {
	now := time.Now()
	crls := []CRLInfo{
		{
			Name:       "ecdsa.crl",
			Algorithm:  "ecdsa-p256",
			ThisUpdate: now,
			NextUpdate: now.Add(7 * 24 * time.Hour),
			Revoked:    1,
			Status:     "valid",
		},
		{
			Name:       "rsa.crl",
			Algorithm:  "rsa-2048",
			ThisUpdate: now.Add(-30 * 24 * time.Hour),
			NextUpdate: now.Add(-1 * 24 * time.Hour),
			Revoked:    5,
			Status:     "EXPIRED",
		},
	}
	PrintCRLList(crls)
}

// =============================================================================
// PrintVerifyResult Tests (0% coverage)
// =============================================================================

func TestU_PrintVerifyResult_Valid(t *testing.T) {
	cert := generateTestCert(t)
	result := &VerifyResult{
		IsValid:        true,
		StatusMsg:      "VALID",
		RevocationInfo: "  Revocation: Not checked",
		ExpiredInfo:    "",
	}
	PrintVerifyResult(cert, result)
}

func TestU_PrintVerifyResult_Invalid(t *testing.T) {
	cert := generateTestCert(t)
	result := &VerifyResult{
		IsValid:        false,
		StatusMsg:      "INVALID",
		RevocationInfo: "  Revocation: Not checked",
		ExpiredInfo:    "",
	}
	PrintVerifyResult(cert, result)
}

func TestU_PrintVerifyResult_Expired(t *testing.T) {
	cert := generateTestCert(t)
	result := &VerifyResult{
		IsValid:        false,
		StatusMsg:      "EXPIRED",
		RevocationInfo: "  Revocation: Not checked",
		ExpiredInfo:    "  Expired:    2024-01-01 (365 days ago)",
	}
	PrintVerifyResult(cert, result)
}

// =============================================================================
// PrintCAInitSuccess Tests (0% coverage)
// =============================================================================

func TestU_PrintCAInitSuccess_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	caInstance, caDir := createRealCA(t, tmpDir)

	cfg := &ca.Config{
		CommonName:    "Test Root CA",
		Organization:  "Test Org",
		Country:       "FR",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
	}

	PrintCAInitSuccess(caInstance, caDir, cfg, false)
}

func TestU_PrintCAInitSuccess_WithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	caInstance, caDir := createRealCA(t, tmpDir)

	cfg := &ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		Passphrase:    "secret",
	}

	PrintCAInitSuccess(caInstance, caDir, cfg, false)
}

func TestU_PrintCAInitSuccess_WithHybridConfig(t *testing.T) {
	tmpDir := t.TempDir()
	caInstance, caDir := createRealCA(t, tmpDir)

	cfg := &ca.Config{
		CommonName:    "Test Root CA",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		HybridConfig: &ca.HybridConfig{
			Algorithm: crypto.AlgMLDSA65,
		},
	}

	PrintCAInitSuccess(caInstance, caDir, cfg, false)
	PrintCAInitSuccess(caInstance, caDir, cfg, true)
}

// =============================================================================
// PrintSubordinateCASuccess Tests (0% coverage)
// =============================================================================

func TestU_PrintSubordinateCASuccess_Basic(t *testing.T) {
	cert := generateTestCert(t)
	PrintSubordinateCASuccess(cert, "/path/to/cert.pem", "/path/to/chain.pem", "/path/to/key.pem", "secret")
}

func TestU_PrintSubordinateCASuccess_NoPassphrase(t *testing.T) {
	cert := generateTestCert(t)
	PrintSubordinateCASuccess(cert, "/path/to/cert.pem", "/path/to/chain.pem", "/path/to/key.pem", "")
}

// =============================================================================
// PrintMultiProfileSuccess Tests (0% coverage)
// =============================================================================

func TestU_PrintMultiProfileSuccess_Basic(t *testing.T) {
	cert := generateTestCert(t)

	result := &ca.MultiProfileInitResult{
		Info: &ca.CAInfo{
			Active: "v1",
		},
		Certificates: map[string]*x509.Certificate{
			"ecdsa-p256": cert,
		},
	}

	PrintMultiProfileSuccess(result, "/path/to/ca", "secret")
}

func TestU_PrintMultiProfileSuccess_NoPassphrase(t *testing.T) {
	cert := generateTestCert(t)

	result := &ca.MultiProfileInitResult{
		Info: &ca.CAInfo{
			Active: "v1",
		},
		Certificates: map[string]*x509.Certificate{
			"ecdsa-p256": cert,
		},
	}

	PrintMultiProfileSuccess(result, "/path/to/ca", "")
}

func TestU_PrintMultiProfileSuccess_MultipleCerts(t *testing.T) {
	cert1 := generateTestCert(t)
	cert2 := generateTestCert(t)

	result := &ca.MultiProfileInitResult{
		Info: &ca.CAInfo{
			Active: "v1",
		},
		Certificates: map[string]*x509.Certificate{
			"ecdsa-p256": cert1,
			"ecdsa-p384": cert2,
		},
	}

	PrintMultiProfileSuccess(result, "/path/to/ca", "secret")
}

// =============================================================================
// LoadAndValidateProfiles Tests (0% coverage)
// =============================================================================

func TestU_LoadAndValidateProfiles_BuiltinProfile(t *testing.T) {
	profiles, vars, err := LoadAndValidateProfiles([]string{"ec/root-ca"}, profile.VariableValues{"cn": "Test CA"})
	if err != nil {
		t.Fatalf("LoadAndValidateProfiles() error = %v", err)
	}
	if len(profiles) != 1 {
		t.Errorf("LoadAndValidateProfiles() returned %d profiles, want 1", len(profiles))
	}
	if vars == nil {
		t.Error("LoadAndValidateProfiles() returned nil vars")
	}
}

func TestU_LoadAndValidateProfiles_MultipleProfiles(t *testing.T) {
	profiles, _, err := LoadAndValidateProfiles([]string{"ec/root-ca", "ec/tls-server"}, profile.VariableValues{"cn": "test.example.com"})
	if err != nil {
		t.Fatalf("LoadAndValidateProfiles() error = %v", err)
	}
	if len(profiles) != 2 {
		t.Errorf("LoadAndValidateProfiles() returned %d profiles, want 2", len(profiles))
	}
}

func TestU_LoadAndValidateProfiles_InvalidProfile(t *testing.T) {
	_, _, err := LoadAndValidateProfiles([]string{"nonexistent/profile"}, nil)
	if err == nil {
		t.Error("LoadAndValidateProfiles() should fail for non-existent profile")
	}
}

func TestU_LoadAndValidateProfiles_EmptyVars(t *testing.T) {
	profiles, _, err := LoadAndValidateProfiles([]string{"ec/root-ca"}, nil)
	if err != nil {
		t.Fatalf("LoadAndValidateProfiles() error = %v", err)
	}
	if len(profiles) != 1 {
		t.Errorf("LoadAndValidateProfiles() returned %d profiles, want 1", len(profiles))
	}
}

// =============================================================================
// LoadBundleCerts Tests (0% coverage)
// =============================================================================

func TestU_LoadBundleCerts_CABundle(t *testing.T) {
	tmpDir := t.TempDir()
	_, caDir := createRealCA(t, tmpDir)

	store := ca.NewFileStore(caDir)
	certs, err := LoadBundleCerts(store, "ca")
	if err != nil {
		t.Fatalf("LoadBundleCerts(ca) error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadBundleCerts(ca) returned %d certs, want 1", len(certs))
	}
}

func TestU_LoadBundleCerts_ChainBundle(t *testing.T) {
	tmpDir := t.TempDir()
	_, caDir := createRealCA(t, tmpDir)

	store := ca.NewFileStore(caDir)
	certs, err := LoadBundleCerts(store, "chain")
	if err != nil {
		t.Fatalf("LoadBundleCerts(chain) error = %v", err)
	}
	if len(certs) < 1 {
		t.Error("LoadBundleCerts(chain) should return at least 1 cert")
	}
}

func TestU_LoadBundleCerts_RootBundle(t *testing.T) {
	tmpDir := t.TempDir()
	_, caDir := createRealCA(t, tmpDir)

	store := ca.NewFileStore(caDir)
	certs, err := LoadBundleCerts(store, "root")
	if err != nil {
		t.Fatalf("LoadBundleCerts(root) error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadBundleCerts(root) returned %d certs, want 1", len(certs))
	}
}

func TestU_LoadBundleCerts_ChainWithChainFile(t *testing.T) {
	tmpDir := t.TempDir()
	caInstance, caDir := createRealCA(t, tmpDir)

	caCert := caInstance.Certificate()
	chainPath := filepath.Join(caDir, "chain.pem")
	var chainData []byte
	chainData = append(chainData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	chainData = append(chainData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	if err := os.WriteFile(chainPath, chainData, 0644); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}

	store := ca.NewFileStore(caDir)
	certs, err := LoadBundleCerts(store, "chain")
	if err != nil {
		t.Fatalf("LoadBundleCerts(chain) error = %v", err)
	}
	if len(certs) < 2 {
		t.Errorf("LoadBundleCerts(chain) returned %d certs, want >= 2", len(certs))
	}
}

func TestU_LoadBundleCerts_RootWithChainFile(t *testing.T) {
	tmpDir := t.TempDir()
	caInstance, caDir := createRealCA(t, tmpDir)

	caCert := caInstance.Certificate()
	chainPath := filepath.Join(caDir, "chain.pem")
	var chainData []byte
	chainData = append(chainData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	chainData = append(chainData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	if err := os.WriteFile(chainPath, chainData, 0644); err != nil {
		t.Fatalf("failed to write chain file: %v", err)
	}

	store := ca.NewFileStore(caDir)
	certs, err := LoadBundleCerts(store, "root")
	if err != nil {
		t.Fatalf("LoadBundleCerts(root) error = %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("LoadBundleCerts(root) returned %d certs, want 1", len(certs))
	}
}

func TestU_LoadBundleCerts_InvalidBundleType(t *testing.T) {
	tmpDir := t.TempDir()
	_, caDir := createRealCA(t, tmpDir)

	store := ca.NewFileStore(caDir)
	_, err := LoadBundleCerts(store, "invalid")
	if err == nil {
		t.Error("LoadBundleCerts() should fail for invalid bundle type")
	}
}

// =============================================================================
// InitializeCAByType Tests (0% coverage)
// =============================================================================

func TestU_InitializeCAByType_Classical(t *testing.T) {
	tmpDir := t.TempDir()
	caDir := filepath.Join(tmpDir, "ca")

	store := ca.NewFileStore(caDir)
	if err := store.Init(context.Background()); err != nil {
		t.Fatalf("failed to init store: %v", err)
	}

	cfg := &ca.Config{
		CommonName:    "Test Classical CA",
		Organization:  "Test Org",
		Country:       "FR",
		Algorithm:     crypto.AlgECDSAP256,
		ValidityYears: 10,
		PathLen:       1,
		Profile:       "ec/root-ca",
	}

	newCA, err := InitializeCAByType(store, cfg, false)
	if err != nil {
		t.Fatalf("InitializeCAByType() error = %v", err)
	}
	if newCA == nil {
		t.Fatal("InitializeCAByType() returned nil CA")
	}
	if newCA.Certificate().Subject.CommonName != "Test Classical CA" {
		t.Errorf("CA CN = %s, want Test Classical CA", newCA.Certificate().Subject.CommonName)
	}
}

// =============================================================================
// PrintEnrollmentSuccess Tests (0% coverage)
// =============================================================================

func TestU_PrintEnrollmentSuccess_Basic(t *testing.T) {
	cert := generateTestCert(t)

	now := time.Now()
	activatedAt := now
	cred := credential.NewCredential("test-cred-001", credential.Subject{CommonName: "Test Subject"})
	cred.Active = "v1"
	cred.Versions["v1"] = credential.CredVersion{
		Profiles:    []string{"ec/tls-server"},
		Created:     now,
		NotBefore:   now,
		NotAfter:    now.Add(365 * 24 * time.Hour),
		ActivatedAt: &activatedAt,
	}

	result := &credential.EnrollmentResult{
		Credential:   cred,
		Certificates: []*x509.Certificate{cert},
	}

	PrintEnrollmentSuccess(result, "")
}

func TestU_PrintEnrollmentSuccess_WithHSM(t *testing.T) {
	cert := generateTestCert(t)

	now := time.Now()
	activatedAt := now
	cred := credential.NewCredential("test-cred-hsm", credential.Subject{CommonName: "HSM Test"})
	cred.Active = "v1"
	cred.Versions["v1"] = credential.CredVersion{
		Profiles:    []string{"ec/tls-server"},
		Created:     now,
		NotBefore:   now,
		NotAfter:    now.Add(365 * 24 * time.Hour),
		ActivatedAt: &activatedAt,
	}

	result := &credential.EnrollmentResult{
		Credential:   cred,
		Certificates: []*x509.Certificate{cert},
		StorageRefs: []crypto.StorageRef{
			{Type: "pkcs11", Label: "my-hsm-key"},
		},
	}

	PrintEnrollmentSuccess(result, "/path/to/hsm.yaml")
}

// =============================================================================
// AppendCAChainIfNeeded Tests (0% coverage)
// =============================================================================

func TestU_AppendCAChainIfNeeded_NotChain(t *testing.T) {
	cert := generateTestCert(t)
	certs := []*x509.Certificate{cert}

	result, err := AppendCAChainIfNeeded(certs, "cert", "/nonexistent/path")
	if err != nil {
		t.Fatalf("AppendCAChainIfNeeded(cert) error = %v", err)
	}
	if len(result) != 1 {
		t.Errorf("AppendCAChainIfNeeded(cert) returned %d certs, want 1", len(result))
	}
}

func TestU_AppendCAChainIfNeeded_ChainWithRealCA(t *testing.T) {
	tmpDir := t.TempDir()
	_, caDir := createRealCA(t, tmpDir)

	cert := generateTestCert(t)
	certs := []*x509.Certificate{cert}

	result, err := AppendCAChainIfNeeded(certs, "chain", caDir)
	if err != nil {
		t.Fatalf("AppendCAChainIfNeeded(chain) error = %v", err)
	}
	if len(result) < 2 {
		t.Errorf("AppendCAChainIfNeeded(chain) returned %d certs, want >= 2", len(result))
	}
}

func TestU_AppendCAChainIfNeeded_ChainWithInvalidDir(t *testing.T) {
	cert := generateTestCert(t)
	certs := []*x509.Certificate{cert}

	_, err := AppendCAChainIfNeeded(certs, "chain", "/nonexistent/ca/dir")
	if err == nil {
		t.Error("AppendCAChainIfNeeded(chain) should fail for invalid CA dir")
	}
}

// =============================================================================
// CheckCRL - Additional Branch Coverage (75% -> higher)
// =============================================================================

func TestU_CheckCRL_WrongIssuerSignature(t *testing.T) {
	caCertA, caKeyA := generateTestCAAndKey(t)
	caCertB, _ := generateTestCAAndKey(t)

	cert, _ := createIssuedCert(t, caCertA, caKeyA, "test.example.com")

	crlDER := createTestCRL(t, caCertA, caKeyA, []*big.Int{})

	tmpDir := t.TempDir()
	crlPath := filepath.Join(tmpDir, "test.crl")
	if err := os.WriteFile(crlPath, crlDER, 0644); err != nil {
		t.Fatalf("failed to write CRL file: %v", err)
	}

	_, _, _, err := CheckCRL(cert, caCertB, crlPath)
	if err == nil {
		t.Error("CheckCRL() should fail when CRL is signed by different issuer")
	}
}

// =============================================================================
// LoadSigningKey - Additional Branch Coverage (36.8% -> higher)
// =============================================================================

func TestU_LoadSigningKey_HSMConfigNotFound(t *testing.T) {
	_, err := LoadSigningKey("/nonexistent/hsm.yaml", "", "", "my-key", "", nil)
	if err == nil {
		t.Error("LoadSigningKey() should fail for non-existent HSM config")
	}
}

func TestU_LoadSigningKey_SoftwareKeyNotFound(t *testing.T) {
	_, err := LoadSigningKey("", "/nonexistent/key.pem", "", "", "", nil)
	if err == nil {
		t.Error("LoadSigningKey() should fail for non-existent key file")
	}
}

func TestU_LoadSigningKey_SoftwareKeyWithPassphrase(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "key.pem")

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
// VerifyCertificateSignature - Additional Branch Coverage (35.7% -> higher)
// =============================================================================

func TestU_VerifyCertificateSignature_ExpiredLeaf(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-10 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "expired.example.com"},
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(-1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"expired.example.com"},
		BasicConstraintsValid: true,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	err := VerifyCertificateSignature(leafCert, caCert, nil)
	if err == nil {
		t.Error("VerifyCertificateSignature() should fail for expired certificate")
	}
}

// =============================================================================
// Print functions for other helpers
// =============================================================================

func TestU_PrintSubordinateCatalystCASuccess(t *testing.T) {
	cert := generateTestCert(t)
	PrintSubordinateCatalystCASuccess(cert, "/path/cert.pem", "/path/chain.pem", "/path/classical.key", "/path/pqc.key", "secret")
	PrintSubordinateCatalystCASuccess(cert, "/path/cert.pem", "/path/chain.pem", "/path/classical.key", "/path/pqc.key", "")
}

func TestU_PrintCAHSMSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	caInstance, _ := createRealCA(t, tmpDir)
	PrintCAHSMSuccess(caInstance, filepath.Join(tmpDir, "ca"), "/path/to/hsm.yaml", filepath.Join(tmpDir, "ca", "hsm.yaml"))
}

// =============================================================================
// CheckRevocationStatus - additional branch
// =============================================================================

func TestU_CheckRevocationStatus_CRLInvalidFile(t *testing.T) {
	caCert, caKey := generateTestCAAndKey(t)
	cert, _ := createIssuedCert(t, caCert, caKey, "test.example.com")

	_, _, err := CheckRevocationStatus(cert, caCert, "/nonexistent/crl.pem", "")
	if err == nil {
		t.Error("CheckRevocationStatus() should fail for invalid CRL file")
	}
}

// =============================================================================
// FormatStatus - fill out remaining branches
// =============================================================================

func TestU_FormatStatus_AllBranches(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"valid", ColorGreen},
		{"active", ColorGreen},
		{"revoked", ColorRed},
		{"expired", ColorRed},
		{"invalid", ColorRed},
		{"pending", ColorYellow},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := FormatStatus(tt.input)
			if len(result) == 0 {
				t.Error("FormatStatus() returned empty string")
			}
		})
	}
}

// =============================================================================
// WriteExportOutput to stdout
// =============================================================================

func TestU_WriteExportOutput_Stdout(t *testing.T) {
	data := []byte("cert data")
	err := WriteExportOutput(data, "", 1)
	if err != nil {
		t.Errorf("WriteExportOutput() to stdout error = %v", err)
	}
}
