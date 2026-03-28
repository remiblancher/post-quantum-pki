package credential

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkicrypto "github.com/qpki/qpki/internal/crypto"
)

// =============================================================================
// EnsureAlgoDir Tests
// =============================================================================

func TestU_EnsureAlgoDir_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath(tmpDir)

	err := cred.EnsureAlgoDir("v1", "ec")
	if err != nil {
		t.Fatalf("EnsureAlgoDir failed: %v", err)
	}

	expected := filepath.Join(tmpDir, "versions", "v1", "ec")
	info, err := os.Stat(expected)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected a directory")
	}
}

func TestU_EnsureAlgoDir_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath(tmpDir)

	// Call twice, should not error
	if err := cred.EnsureAlgoDir("v1", "rsa"); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if err := cred.EnsureAlgoDir("v1", "rsa"); err != nil {
		t.Fatalf("second call failed: %v", err)
	}
}

func TestU_EnsureAlgoDir_MultipleAlgos(t *testing.T) {
	tmpDir := t.TempDir()
	cred := NewCredential("test", Subject{CommonName: "Test"})
	cred.SetBasePath(tmpDir)

	algos := []string{"ec", "rsa", "ml-dsa"}
	for _, algo := range algos {
		if err := cred.EnsureAlgoDir("v1", algo); err != nil {
			t.Fatalf("EnsureAlgoDir(%q) failed: %v", algo, err)
		}
	}

	for _, algo := range algos {
		path := filepath.Join(tmpDir, "versions", "v1", algo)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("directory for algo %q not found: %v", algo, err)
		}
	}
}

// =============================================================================
// createDir Tests
// =============================================================================

func TestU_createDir_Basic(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "a", "b", "c")

	err := createDir(target)
	if err != nil {
		t.Fatalf("createDir failed: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected a directory")
	}
}

func TestU_createDir_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "exists")

	if err := createDir(target); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if err := createDir(target); err != nil {
		t.Fatalf("second call failed: %v", err)
	}
}

func TestU_createDir_ExistingDir(t *testing.T) {
	tmpDir := t.TempDir()
	// tmpDir already exists
	if err := createDir(tmpDir); err != nil {
		t.Fatalf("createDir on existing dir failed: %v", err)
	}
}

// =============================================================================
// allSignersPQC Tests
// =============================================================================

// mockSigner implements pkicrypto.Signer for testing.
type mockSigner struct {
	alg pkicrypto.AlgorithmID
}

func (m *mockSigner) Public() crypto.PublicKey         { return nil }
func (m *mockSigner) Algorithm() pkicrypto.AlgorithmID { return m.alg }
func (m *mockSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}

func TestU_allSignersPQC_AllPQC(t *testing.T) {
	signers := []pkicrypto.Signer{
		&mockSigner{alg: pkicrypto.AlgMLDSA44},
		&mockSigner{alg: pkicrypto.AlgMLDSA65},
	}
	if !allSignersPQC(signers) {
		t.Error("expected true for all-PQC signers")
	}
}

func TestU_allSignersPQC_MixedSigners(t *testing.T) {
	signers := []pkicrypto.Signer{
		&mockSigner{alg: pkicrypto.AlgMLDSA44},
		&mockSigner{alg: pkicrypto.AlgECDSAP256},
	}
	if allSignersPQC(signers) {
		t.Error("expected false for mixed signers")
	}
}

func TestU_allSignersPQC_AllClassical(t *testing.T) {
	signers := []pkicrypto.Signer{
		&mockSigner{alg: pkicrypto.AlgECDSAP256},
		&mockSigner{alg: pkicrypto.AlgRSA2048},
	}
	if allSignersPQC(signers) {
		t.Error("expected false for all-classical signers")
	}
}

func TestU_allSignersPQC_EmptySlice(t *testing.T) {
	signers := []pkicrypto.Signer{}
	if !allSignersPQC(signers) {
		t.Error("expected true for empty slice (vacuous truth)")
	}
}

func TestU_allSignersPQC_SinglePQC(t *testing.T) {
	signers := []pkicrypto.Signer{
		&mockSigner{alg: pkicrypto.AlgMLDSA87},
	}
	if !allSignersPQC(signers) {
		t.Error("expected true for single PQC signer")
	}
}

func TestU_allSignersPQC_SingleClassical(t *testing.T) {
	signers := []pkicrypto.Signer{
		&mockSigner{alg: pkicrypto.AlgECDSAP384},
	}
	if allSignersPQC(signers) {
		t.Error("expected false for single classical signer")
	}
}

// =============================================================================
// issuerEqualFieldByField Tests
// =============================================================================

func makeRDN(oid asn1.ObjectIdentifier, value string) pkix.RelativeDistinguishedNameSET {
	return pkix.RelativeDistinguishedNameSET{
		{Type: oid, Value: value},
	}
}

func TestU_issuerEqualFieldByField_Identical(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}

	a := pkix.RDNSequence{makeRDN(cn, "Test CA"), makeRDN(org, "Test Org")}
	b := pkix.RDNSequence{makeRDN(cn, "Test CA"), makeRDN(org, "Test Org")}

	if !issuerEqualFieldByField(a, b) {
		t.Error("expected identical RDN sequences to be equal")
	}
}

func TestU_issuerEqualFieldByField_DifferentValues(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}

	a := pkix.RDNSequence{makeRDN(cn, "CA A")}
	b := pkix.RDNSequence{makeRDN(cn, "CA B")}

	if issuerEqualFieldByField(a, b) {
		t.Error("expected different values to be not equal")
	}
}

func TestU_issuerEqualFieldByField_DifferentLengths(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}

	a := pkix.RDNSequence{makeRDN(cn, "Test")}
	b := pkix.RDNSequence{makeRDN(cn, "Test"), makeRDN(org, "Extra")}

	if issuerEqualFieldByField(a, b) {
		t.Error("expected different-length sequences to be not equal")
	}
}

func TestU_issuerEqualFieldByField_DifferentOIDs(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}

	a := pkix.RDNSequence{makeRDN(cn, "Test")}
	b := pkix.RDNSequence{makeRDN(org, "Test")}

	if issuerEqualFieldByField(a, b) {
		t.Error("expected different OIDs to be not equal")
	}
}

func TestU_issuerEqualFieldByField_Empty(t *testing.T) {
	a := pkix.RDNSequence{}
	b := pkix.RDNSequence{}

	if !issuerEqualFieldByField(a, b) {
		t.Error("expected empty sequences to be equal")
	}
}

func TestU_issuerEqualFieldByField_DifferentRDNSetLengths(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}

	a := pkix.RDNSequence{
		{
			{Type: cn, Value: "Test"},
			{Type: org, Value: "Org"},
		},
	}
	b := pkix.RDNSequence{
		{
			{Type: cn, Value: "Test"},
		},
	}

	if issuerEqualFieldByField(a, b) {
		t.Error("expected different RDN set lengths to be not equal")
	}
}

// =============================================================================
// FileStore.ListVersions Tests
// =============================================================================

func TestU_FileStore_ListVersions_Versioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a versioned credential
	cred := NewCredential("test-versions", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().AddDate(1, 0, 0)
	cred.Versions["v1"] = ver

	cert := generateTestCertificate(t)
	if err := store.Save(ctx, cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	versions, err := store.ListVersions(ctx, "test-versions")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}

	if len(versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(versions))
	}
	if versions[0] != "v1" {
		t.Errorf("expected version 'v1', got '%s'", versions[0])
	}
}

func TestU_FileStore_ListVersions_NonVersioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a credential without versions (legacy)
	cred := NewCredential("legacy-cred", Subject{CommonName: "Legacy"})
	if err := store.Save(ctx, cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	versions, err := store.ListVersions(ctx, "legacy-cred")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}

	// Non-versioned credentials should return implicit v1
	if len(versions) != 1 || versions[0] != "v1" {
		t.Errorf("expected [v1] for non-versioned credential, got %v", versions)
	}
}

func TestU_FileStore_ListVersions_ContextCanceled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.ListVersions(ctx, "any-cred")
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

// =============================================================================
// FileStore.LoadCertificatesForVersion Tests
// =============================================================================

func TestU_FileStore_LoadCertificatesForVersion_NewStructure(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a versioned credential with certs
	cred := NewCredential("cert-ver-test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().AddDate(1, 0, 0)
	cred.Versions["v1"] = ver

	cert := generateTestCertificate(t)
	if err := store.Save(ctx, cred, []*x509.Certificate{cert}, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	certs, err := store.LoadCertificatesForVersion(ctx, "cert-ver-test", "v1")
	if err != nil {
		t.Fatalf("LoadCertificatesForVersion failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

func TestU_FileStore_LoadCertificatesForVersion_OldStructure(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a versioned credential metadata
	cred := NewCredential("old-struct", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().AddDate(1, 0, 0)
	cred.Versions["v1"] = ver

	// Save metadata only (no certs via Save)
	if err := store.Save(ctx, cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Manually create old-style algo directory structure
	credPath := filepath.Join(tmpDir, "old-struct")
	versionDir := filepath.Join(credPath, "versions", "v1")
	algoDir := filepath.Join(versionDir, "ecdsa-p256")
	if err := os.MkdirAll(algoDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Write certificate in old-style location
	cert := generateTestCertificate(t)
	certsPEM, err := EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("EncodeCertificatesPEM failed: %v", err)
	}
	certPath := filepath.Join(algoDir, "certificates.pem")
	if err := os.WriteFile(certPath, certsPEM, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	certs, err := store.LoadCertificatesForVersion(ctx, "old-struct", "v1")
	if err != nil {
		t.Fatalf("LoadCertificatesForVersion failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate from old structure, got %d", len(certs))
	}
}

func TestU_FileStore_LoadCertificatesForVersion_VersionNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a versioned credential
	cred := NewCredential("ver-not-found", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	if err := store.Save(ctx, cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	_, err := store.LoadCertificatesForVersion(ctx, "ver-not-found", "v999")
	if err == nil {
		t.Fatal("expected error for non-existent version")
	}
}

func TestU_FileStore_LoadCertificatesForVersion_ContextCanceled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.LoadCertificatesForVersion(ctx, "any-cred", "v1")
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

// =============================================================================
// FileStore.LoadKeysForVersion Tests
// =============================================================================

func TestU_FileStore_LoadKeysForVersion_NewStructure(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a versioned credential with keys
	cred := NewCredential("key-ver-test", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().AddDate(1, 0, 0)
	cred.Versions["v1"] = ver

	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner failed: %v", err)
	}

	cert := generateCertForSigner(t, signer)
	passphrase := []byte("test-passphrase")

	if err := store.Save(ctx, cred, []*x509.Certificate{cert}, []pkicrypto.Signer{signer}, passphrase); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	signers, err := store.LoadKeysForVersion(ctx, "key-ver-test", "v1", passphrase)
	if err != nil {
		t.Fatalf("LoadKeysForVersion failed: %v", err)
	}

	if len(signers) != 1 {
		t.Errorf("expected 1 signer, got %d", len(signers))
	}
}

func TestU_FileStore_LoadKeysForVersion_OldStructure(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a versioned credential metadata
	cred := NewCredential("old-keys", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().AddDate(1, 0, 0)
	cred.Versions["v1"] = ver

	if err := store.Save(ctx, cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Manually create old-style algo directory with keys
	credPath := filepath.Join(tmpDir, "old-keys")
	versionDir := filepath.Join(credPath, "versions", "v1")
	algoDir := filepath.Join(versionDir, "ecdsa-p256")
	if err := os.MkdirAll(algoDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Generate and save key in old-style location
	signer, err := pkicrypto.GenerateSoftwareSigner(pkicrypto.AlgECDSAP256)
	if err != nil {
		t.Fatalf("GenerateSoftwareSigner failed: %v", err)
	}

	passphrase := []byte("test-passphrase")
	keysPEM, err := EncodePrivateKeysPEM([]pkicrypto.Signer{signer}, passphrase)
	if err != nil {
		t.Fatalf("EncodePrivateKeysPEM failed: %v", err)
	}

	keyPath := filepath.Join(algoDir, "private-keys.pem")
	if err := os.WriteFile(keyPath, keysPEM, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	signers, err := store.LoadKeysForVersion(ctx, "old-keys", "v1", passphrase)
	if err != nil {
		t.Fatalf("LoadKeysForVersion failed: %v", err)
	}

	if len(signers) != 1 {
		t.Errorf("expected 1 signer from old structure, got %d", len(signers))
	}
}

func TestU_FileStore_LoadKeysForVersion_VersionNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a versioned credential
	cred := NewCredential("keys-not-found", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/signing"}, []string{"ec"})
	if err := store.Save(ctx, cred, nil, nil, nil); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	_, err := store.LoadKeysForVersion(ctx, "keys-not-found", "v999", nil)
	if err == nil {
		t.Fatal("expected error for non-existent version")
	}
}

func TestU_FileStore_LoadKeysForVersion_ContextCanceled(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.LoadKeysForVersion(ctx, "any-cred", "v1", nil)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

// =============================================================================
// classicalKeyInfo Tests (improve branch coverage)
// =============================================================================

func TestU_classicalKeyInfo_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	alg, pub := classicalKeyInfo(key)
	if alg != pkicrypto.AlgRSA2048 {
		t.Errorf("expected AlgRSA2048, got %s", alg)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected *rsa.PublicKey")
	}
	if rsaPub.N.Cmp(key.PublicKey.N) != 0 {
		t.Error("public key mismatch")
	}
}

func TestU_classicalKeyInfo_ECDSAP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	alg, pub := classicalKeyInfo(key)
	if alg != pkicrypto.AlgECDSAP256 {
		t.Errorf("expected AlgECDSAP256, got %s", alg)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestU_classicalKeyInfo_ECDSAP384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	alg, pub := classicalKeyInfo(key)
	if alg != pkicrypto.AlgECDSAP384 {
		t.Errorf("expected AlgECDSAP384, got %s", alg)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestU_classicalKeyInfo_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	alg, pub := classicalKeyInfo(priv)
	if alg != pkicrypto.AlgEd25519 {
		t.Errorf("expected AlgEd25519, got %s", alg)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestU_classicalKeyInfo_UnsupportedECDSACurve(t *testing.T) {
	// P-521 is not in the switch, should return ("", nil)
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	alg, pub := classicalKeyInfo(key)
	if alg != "" {
		t.Errorf("expected empty algorithm for unsupported curve, got %s", alg)
	}
	if pub != nil {
		t.Error("expected nil public key for unsupported curve")
	}
}

func TestU_classicalKeyInfo_UnknownType(t *testing.T) {
	// Pass a non-key type
	alg, pub := classicalKeyInfo("not-a-key")
	if alg != "" {
		t.Errorf("expected empty algorithm for unknown type, got %s", alg)
	}
	if pub != nil {
		t.Error("expected nil public key for unknown type")
	}
}

// =============================================================================
// Decode PKCS#8 -> classicalKeyInfo integration (pem.go line ~258-268)
// =============================================================================

func TestU_DecodePrivateKeyPEM_RSA_PKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal to PKCS#8
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	signers, err := DecodePrivateKeysPEM(pemBlock, nil)
	if err != nil {
		t.Fatalf("DecodePrivateKeysPEM failed: %v", err)
	}

	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}
	if signers[0].Algorithm() != pkicrypto.AlgRSA2048 {
		t.Errorf("expected AlgRSA2048, got %s", signers[0].Algorithm())
	}
}

func TestU_DecodePrivateKeyPEM_Ed25519_PKCS8(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal PKCS#8: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	signers, err := DecodePrivateKeysPEM(pemBlock, nil)
	if err != nil {
		t.Fatalf("DecodePrivateKeysPEM failed: %v", err)
	}

	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}
	if signers[0].Algorithm() != pkicrypto.AlgEd25519 {
		t.Errorf("expected AlgEd25519, got %s", signers[0].Algorithm())
	}
}

// =============================================================================
// FileStore.ListVersions with multiple versions
// =============================================================================

func TestU_FileStore_ListVersions_MultipleVersions(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a credential with two versions
	cred := NewCredential("multi-ver", Subject{CommonName: "Test"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	ver1 := cred.Versions["v1"]
	ver1.NotBefore = time.Now()
	ver1.NotAfter = time.Now().AddDate(1, 0, 0)
	cred.Versions["v1"] = ver1

	cert1 := generateTestCertificate(t)
	if err := store.Save(ctx, cred, []*x509.Certificate{cert1}, nil, nil); err != nil {
		t.Fatalf("Save v1 failed: %v", err)
	}

	// Add a second version
	now := time.Now()
	cred.Versions["v2"] = CredVersion{
		Profiles:    []string{"ec/tls-server"},
		Algos:       []string{"ec"},
		ActivatedAt: &now,
		NotBefore:   now,
		NotAfter:    now.AddDate(1, 0, 0),
	}
	// Archive v1
	v1 := cred.Versions["v1"]
	v1.ArchivedAt = &now
	cred.Versions["v1"] = v1
	cred.Active = "v2"

	cert2 := generateTestCertificate(t)
	if err := store.Save(ctx, cred, []*x509.Certificate{cert2}, nil, nil); err != nil {
		t.Fatalf("Save v2 failed: %v", err)
	}

	versions, err := store.ListVersions(ctx, "multi-ver")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}

	if len(versions) < 2 {
		t.Errorf("expected at least 2 versions, got %d: %v", len(versions), versions)
	}
}

// =============================================================================
// LoadCertificatesForVersion on non-versioned (legacy) credential
// =============================================================================

func TestU_FileStore_LoadCertificatesForVersion_NonVersioned(t *testing.T) {
	tmpDir := t.TempDir()
	store := NewFileStore(tmpDir)
	ctx := context.Background()

	// Create a credential with a version but store certs in the legacy flat location.
	// The credential has versions metadata but no versions/ directory on disk,
	// so IsVersioned() returns false and it falls back to loadActiveCertificatesUnlocked.
	cred := NewCredential("legacy-cert", Subject{CommonName: "Legacy"})
	cred.CreateInitialVersion([]string{"ec/tls-server"}, []string{"ec"})
	ver := cred.Versions["v1"]
	ver.NotBefore = time.Now()
	ver.NotAfter = time.Now().AddDate(1, 0, 0)
	cred.Versions["v1"] = ver

	// Save metadata manually (not through store.Save which creates version dirs)
	credDir := filepath.Join(tmpDir, "legacy-cert")
	if err := os.MkdirAll(credDir, 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	cred.SetBasePath(credDir)
	if err := cred.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Write a cert using the versioned structure that loadActiveCertificatesUnlocked expects
	cert := generateTestCertificate(t)
	certsPEM, err := EncodeCertificatesPEM([]*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("EncodeCertificatesPEM failed: %v", err)
	}
	certsDir := filepath.Join(credDir, "versions", "v1", "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(certsDir, "credential.ec.pem"), certsPEM, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// LoadCertificatesForVersion should work via the active version path
	certs, err := store.LoadCertificatesForVersion(ctx, "legacy-cert", "v1")
	if err != nil {
		t.Fatalf("LoadCertificatesForVersion failed: %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(certs))
	}
}

// =============================================================================
// issuerEqualFieldByField with multi-attribute RDNs
// =============================================================================

func TestU_issuerEqualFieldByField_MultiAttribute(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	org := asn1.ObjectIdentifier{2, 5, 4, 10}
	country := asn1.ObjectIdentifier{2, 5, 4, 6}

	// Single RDN set with multiple attributes
	a := pkix.RDNSequence{
		{
			{Type: cn, Value: "Test"},
			{Type: org, Value: "Org"},
		},
		makeRDN(country, "US"),
	}
	b := pkix.RDNSequence{
		{
			{Type: cn, Value: "Test"},
			{Type: org, Value: "Org"},
		},
		makeRDN(country, "US"),
	}

	if !issuerEqualFieldByField(a, b) {
		t.Error("expected multi-attribute RDNs to be equal")
	}

	// Change one attribute value
	c := pkix.RDNSequence{
		{
			{Type: cn, Value: "Test"},
			{Type: org, Value: "Different"},
		},
		makeRDN(country, "US"),
	}

	if issuerEqualFieldByField(a, c) {
		t.Error("expected different multi-attribute RDNs to be not equal")
	}
}

// =============================================================================
// Helper: generate a self-signed cert with a custom issuer for testing
// =============================================================================

func generateTestCertWithIssuer(t *testing.T, subject pkix.Name) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}
