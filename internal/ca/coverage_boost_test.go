package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"testing"
	"time"

	pkicrypto "github.com/qpki/qpki/internal/crypto"
	"github.com/qpki/qpki/internal/profile"
)

// testSigner is a minimal mock implementing pkicrypto.Signer for unit tests.
type testSigner struct {
	key  *ecdsa.PrivateKey
	algo pkicrypto.AlgorithmID
}

func newTestSigner(algo pkicrypto.AlgorithmID) *testSigner {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &testSigner{key: key, algo: algo}
}

func (s *testSigner) Public() crypto.PublicKey         { return s.key.Public() }
func (s *testSigner) Algorithm() pkicrypto.AlgorithmID { return s.algo }
func (s *testSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(rand, digest, opts)
}

// =============================================================================
// SignerForAlgo / CertForAlgo Tests
// =============================================================================

func TestU_CA_SignerForAlgo(t *testing.T) {
	defaultSigner := newTestSigner(pkicrypto.AlgECDSAP256)
	ecSigner := newTestSigner(pkicrypto.AlgECDSAP384)
	mldsaSigner := newTestSigner(pkicrypto.AlgMLDSA65)

	t.Run("returns per-algo signer when present", func(t *testing.T) {
		ca := &CA{
			signer: defaultSigner,
			signers: map[string]pkicrypto.Signer{
				"ec":     ecSigner,
				"ml-dsa": mldsaSigner,
			},
		}

		got := ca.SignerForAlgo("ec")
		if got != ecSigner {
			t.Error("SignerForAlgo(ec) should return the EC signer")
		}

		got = ca.SignerForAlgo("ml-dsa")
		if got != mldsaSigner {
			t.Error("SignerForAlgo(ml-dsa) should return the ML-DSA signer")
		}
	})

	t.Run("falls back to default signer for unknown algo", func(t *testing.T) {
		ca := &CA{
			signer: defaultSigner,
			signers: map[string]pkicrypto.Signer{
				"ec": ecSigner,
			},
		}

		got := ca.SignerForAlgo("unknown-algo")
		if got != defaultSigner {
			t.Error("SignerForAlgo(unknown) should fall back to default signer")
		}
	})

	t.Run("falls back to default signer when signers map is nil", func(t *testing.T) {
		ca := &CA{
			signer:  defaultSigner,
			signers: nil,
		}

		got := ca.SignerForAlgo("ec")
		if got != defaultSigner {
			t.Error("SignerForAlgo should fall back to default when signers is nil")
		}
	})

	t.Run("falls back to default signer when signers map is empty", func(t *testing.T) {
		ca := &CA{
			signer:  defaultSigner,
			signers: map[string]pkicrypto.Signer{},
		}

		got := ca.SignerForAlgo("ec")
		if got != defaultSigner {
			t.Error("SignerForAlgo should fall back to default when signers map is empty")
		}
	})
}

func TestU_CA_CertForAlgo(t *testing.T) {
	defaultCert := &x509.Certificate{Subject: pkix.Name{CommonName: "Default CA"}}
	ecCert := &x509.Certificate{Subject: pkix.Name{CommonName: "EC CA"}}
	mldsaCert := &x509.Certificate{Subject: pkix.Name{CommonName: "ML-DSA CA"}}

	t.Run("returns per-algo cert when present", func(t *testing.T) {
		ca := &CA{
			cert: defaultCert,
			certs: map[string]*x509.Certificate{
				"ec":     ecCert,
				"ml-dsa": mldsaCert,
			},
		}

		got := ca.CertForAlgo("ec")
		if got != ecCert {
			t.Errorf("CertForAlgo(ec) = %v, want EC cert", got.Subject.CommonName)
		}

		got = ca.CertForAlgo("ml-dsa")
		if got != mldsaCert {
			t.Errorf("CertForAlgo(ml-dsa) = %v, want ML-DSA cert", got.Subject.CommonName)
		}
	})

	t.Run("falls back to default cert for unknown algo", func(t *testing.T) {
		ca := &CA{
			cert: defaultCert,
			certs: map[string]*x509.Certificate{
				"ec": ecCert,
			},
		}

		got := ca.CertForAlgo("unknown-algo")
		if got != defaultCert {
			t.Error("CertForAlgo(unknown) should fall back to default cert")
		}
	})

	t.Run("falls back to default cert when certs map is nil", func(t *testing.T) {
		ca := &CA{
			cert:  defaultCert,
			certs: nil,
		}

		got := ca.CertForAlgo("ec")
		if got != defaultCert {
			t.Error("CertForAlgo should fall back to default when certs is nil")
		}
	})

	t.Run("falls back to default cert when certs map is empty", func(t *testing.T) {
		ca := &CA{
			cert:  defaultCert,
			certs: map[string]*x509.Certificate{},
		}

		got := ca.CertForAlgo("ec")
		if got != defaultCert {
			t.Error("CertForAlgo should fall back to default when certs map is empty")
		}
	})
}

// =============================================================================
// GetVersionClassicalKey / GetVersionPQCKey Tests
// =============================================================================

func TestU_CAInfo_GetVersionClassicalKey(t *testing.T) {
	info := buildCAInfoWithKeys()

	t.Run("returns classical key for valid version", func(t *testing.T) {
		key := info.GetVersionClassicalKey("v1")
		if key == nil {
			t.Fatal("GetVersionClassicalKey(v1) returned nil")
		}
		if key.ID != "classical" {
			t.Errorf("key.ID = %q, want %q", key.ID, "classical")
		}
		if key.Algorithm != pkicrypto.AlgECDSAP384 {
			t.Errorf("key.Algorithm = %v, want %v", key.Algorithm, pkicrypto.AlgECDSAP384)
		}
	})

	t.Run("returns nil for version without classical key", func(t *testing.T) {
		key := info.GetVersionClassicalKey("v2")
		if key != nil {
			t.Error("GetVersionClassicalKey(v2) should return nil for PQC-only version")
		}
	})

	t.Run("returns nil for non-existent version", func(t *testing.T) {
		key := info.GetVersionClassicalKey("v99")
		if key != nil {
			t.Error("GetVersionClassicalKey(v99) should return nil")
		}
	})
}

func TestU_CAInfo_GetVersionPQCKey(t *testing.T) {
	info := buildCAInfoWithKeys()

	t.Run("returns PQC key for valid version", func(t *testing.T) {
		key := info.GetVersionPQCKey("v1")
		if key == nil {
			t.Fatal("GetVersionPQCKey(v1) returned nil")
		}
		if key.ID != "pqc" {
			t.Errorf("key.ID = %q, want %q", key.ID, "pqc")
		}
		if key.Algorithm != pkicrypto.AlgMLDSA87 {
			t.Errorf("key.Algorithm = %v, want %v", key.Algorithm, pkicrypto.AlgMLDSA87)
		}
	})

	t.Run("returns nil for version without PQC key", func(t *testing.T) {
		key := info.GetVersionPQCKey("v3")
		if key != nil {
			t.Error("GetVersionPQCKey(v3) should return nil for classical-only version")
		}
	})

	t.Run("returns nil for non-existent version", func(t *testing.T) {
		key := info.GetVersionPQCKey("v99")
		if key != nil {
			t.Error("GetVersionPQCKey(v99) should return nil")
		}
	})
}

// =============================================================================
// IsVersionHSMBased Tests
// =============================================================================

func TestU_CAInfo_IsVersionHSMBased(t *testing.T) {
	now := time.Now()
	info := &CAInfo{
		Active: "v1",
		Versions: map[string]CAVersion{
			"v1": {
				Algos:   []string{"ec"},
				Created: now,
				Keys: []KeyRef{
					{
						ID:        "default",
						Algorithm: pkicrypto.AlgECDSAP384,
						Storage:   CreateSoftwareKeyRef("versions/v1/keys/ca.ecdsa-p384.key"),
					},
				},
			},
			"v2": {
				Algos:   []string{"ec"},
				Created: now,
				Keys: []KeyRef{
					{
						ID:        "default",
						Algorithm: pkicrypto.AlgECDSAP384,
						Storage: pkicrypto.StorageRef{
							Type:   "pkcs11",
							Config: "hsm-config.yaml",
						},
					},
				},
			},
			"v3": {
				Algos:   []string{"ec", "ml-dsa"},
				Created: now,
				Keys: []KeyRef{
					{
						ID:        "classical",
						Algorithm: pkicrypto.AlgECDSAP384,
						Storage:   CreateSoftwareKeyRef("versions/v3/keys/ca.ecdsa-p384.key"),
					},
					{
						ID:        "pqc",
						Algorithm: pkicrypto.AlgMLDSA87,
						Storage: pkicrypto.StorageRef{
							Type:   "pkcs11",
							Config: "hsm-config.yaml",
						},
					},
				},
			},
			"v4": {
				Algos:   []string{"ec"},
				Created: now,
				Keys:    []KeyRef{}, // no keys
			},
		},
	}

	t.Run("software-only version returns false", func(t *testing.T) {
		if info.IsVersionHSMBased("v1") {
			t.Error("IsVersionHSMBased(v1) should be false for software-only keys")
		}
	})

	t.Run("HSM-only version returns true", func(t *testing.T) {
		if !info.IsVersionHSMBased("v2") {
			t.Error("IsVersionHSMBased(v2) should be true for HSM-based keys")
		}
	})

	t.Run("mixed HSM+software version returns true", func(t *testing.T) {
		if !info.IsVersionHSMBased("v3") {
			t.Error("IsVersionHSMBased(v3) should be true when any key is HSM-based")
		}
	})

	t.Run("version with no keys returns false", func(t *testing.T) {
		if info.IsVersionHSMBased("v4") {
			t.Error("IsVersionHSMBased(v4) should be false for version with no keys")
		}
	})

	t.Run("non-existent version returns false", func(t *testing.T) {
		if info.IsVersionHSMBased("v99") {
			t.Error("IsVersionHSMBased(v99) should be false for non-existent version")
		}
	})
}

// =============================================================================
// loadMultiProfileSigners (via InitializeMultiProfile + New + LoadSigner)
// =============================================================================

func TestF_CA_LoadMultiProfileSigners(t *testing.T) {
	tmpDir := t.TempDir()

	profEC := &profile.Profile{
		Name:      "test-ec",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	profMLDSA := &profile.Profile{
		Name:      "test-mldsa",
		Algorithm: pkicrypto.AlgMLDSA65,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	passphrase := "test-multi-password"

	cfg := MultiProfileInitConfig{
		Profiles: []ProfileInitConfig{
			{
				Profile:       profEC,
				ValidityYears: 10,
				PathLen:       1,
			},
			{
				Profile:       profMLDSA,
				ValidityYears: 10,
				PathLen:       1,
			},
		},
		Variables: map[string]string{
			"cn": "Test Multi-Profile Signer CA",
			"o":  "Test Org",
			"c":  "US",
		},
		Passphrase: passphrase,
	}

	result, err := InitializeMultiProfile(tmpDir, cfg)
	if err != nil {
		t.Fatalf("InitializeMultiProfile() error = %v", err)
	}
	if result == nil {
		t.Fatal("InitializeMultiProfile() returned nil")
	}

	// Load CA from disk
	store := NewFileStore(tmpDir)
	caObj, err := New(store)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Load signer (should trigger loadMultiProfileSigners for multi-profile CA)
	if err := caObj.LoadSigner(passphrase); err != nil {
		t.Fatalf("LoadSigner() error = %v", err)
	}

	// Verify per-algo signers are populated
	t.Run("default signer is set", func(t *testing.T) {
		if caObj.Signer() == nil {
			t.Error("default signer should not be nil after LoadSigner")
		}
	})

	t.Run("EC signer is available via SignerForAlgo", func(t *testing.T) {
		s := caObj.SignerForAlgo("ec")
		if s == nil {
			t.Error("SignerForAlgo(ec) should return a signer")
		}
	})

	t.Run("ML-DSA signer is available via SignerForAlgo", func(t *testing.T) {
		s := caObj.SignerForAlgo("ml-dsa")
		if s == nil {
			t.Error("SignerForAlgo(ml-dsa) should return a signer")
		}
	})

	t.Run("EC cert is available via CertForAlgo", func(t *testing.T) {
		c := caObj.CertForAlgo("ec")
		if c == nil {
			t.Error("CertForAlgo(ec) should return a certificate")
		}
	})

	t.Run("ML-DSA cert is available via CertForAlgo", func(t *testing.T) {
		c := caObj.CertForAlgo("ml-dsa")
		if c == nil {
			t.Error("CertForAlgo(ml-dsa) should return a certificate")
		}
	})

	t.Run("unknown algo falls back to default", func(t *testing.T) {
		s := caObj.SignerForAlgo("nonexistent")
		if s == nil {
			t.Error("SignerForAlgo(nonexistent) should fall back to default signer")
		}
		if s != caObj.Signer() {
			t.Error("fallback signer should be the default signer")
		}
	})
}

// =============================================================================
// addKeyRefsToVersionMulti Tests
// =============================================================================

func TestF_addKeyRefsToVersionMulti_SingleAlgo(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a minimal CA on disk with ca.meta.json
	info := &CAInfo{
		Subject: Subject{CommonName: "Test CA"},
		Active:  "v1",
		Versions: map[string]CAVersion{
			"v1": {
				Profiles: []string{"test"},
				Algos:    []string{"ec"},
				Created:  time.Now(),
			},
			"v2": {
				Profiles: []string{"test"},
				Algos:    []string{"ec"},
				Created:  time.Now(),
			},
		},
	}
	info.SetBasePath(tmpDir)
	if err := info.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Single-algorithm profile
	prof := &profile.Profile{
		Name:      "test-ec",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	// CA with no keyRefs (software keys, single algo)
	newCA := &CA{}

	err := addKeyRefsToVersionMulti(tmpDir, "v2", prof, newCA)
	if err != nil {
		t.Fatalf("addKeyRefsToVersionMulti() error = %v", err)
	}

	// Reload and check
	reloaded, err := LoadCAInfo(tmpDir)
	if err != nil {
		t.Fatalf("LoadCAInfo() error = %v", err)
	}

	ver := reloaded.Versions["v2"]
	if len(ver.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(ver.Keys))
	}
	if ver.Keys[0].ID != "default" {
		t.Errorf("key ID = %q, want %q", ver.Keys[0].ID, "default")
	}
	if ver.Keys[0].Storage.Type != "software" {
		t.Errorf("storage type = %q, want %q", ver.Keys[0].Storage.Type, "software")
	}
}

func TestF_addKeyRefsToVersionMulti_CatalystProfile(t *testing.T) {
	tmpDir := t.TempDir()

	info := &CAInfo{
		Subject: Subject{CommonName: "Catalyst CA"},
		Active:  "v1",
		Versions: map[string]CAVersion{
			"v1": {
				Profiles: []string{"catalyst"},
				Algos:    []string{"ec", "ml-dsa"},
				Created:  time.Now(),
			},
			"v2": {
				Profiles: []string{"catalyst"},
				Algos:    []string{"ec", "ml-dsa"},
				Created:  time.Now(),
			},
		},
	}
	info.SetBasePath(tmpDir)
	if err := info.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Catalyst profile (hybrid, 2 algorithms)
	prof := &profile.Profile{
		Name:       "catalyst-test",
		Mode:       profile.ModeCatalyst,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87},
		Validity:   10 * 365 * 24 * time.Hour,
	}

	newCA := &CA{}

	err := addKeyRefsToVersionMulti(tmpDir, "v2", prof, newCA)
	if err != nil {
		t.Fatalf("addKeyRefsToVersionMulti() error = %v", err)
	}

	reloaded, err := LoadCAInfo(tmpDir)
	if err != nil {
		t.Fatalf("LoadCAInfo() error = %v", err)
	}

	ver := reloaded.Versions["v2"]
	if len(ver.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(ver.Keys))
	}

	// Check classical key
	var foundClassical, foundPQC bool
	for _, k := range ver.Keys {
		if k.ID == "classical" {
			foundClassical = true
			if k.Algorithm != pkicrypto.AlgECDSAP384 {
				t.Errorf("classical key algorithm = %v, want %v", k.Algorithm, pkicrypto.AlgECDSAP384)
			}
		}
		if k.ID == "pqc" {
			foundPQC = true
			if k.Algorithm != pkicrypto.AlgMLDSA87 {
				t.Errorf("PQC key algorithm = %v, want %v", k.Algorithm, pkicrypto.AlgMLDSA87)
			}
		}
	}
	if !foundClassical {
		t.Error("classical key reference not found")
	}
	if !foundPQC {
		t.Error("PQC key reference not found")
	}
}

func TestF_addKeyRefsToVersionMulti_CompositeProfile(t *testing.T) {
	tmpDir := t.TempDir()

	info := &CAInfo{
		Subject: Subject{CommonName: "Composite CA"},
		Active:  "v1",
		Versions: map[string]CAVersion{
			"v1": {
				Profiles: []string{"composite"},
				Algos:    []string{"ec", "ml-dsa"},
				Created:  time.Now(),
			},
			"v2": {
				Profiles: []string{"composite"},
				Algos:    []string{"ec", "ml-dsa"},
				Created:  time.Now(),
			},
		},
	}
	info.SetBasePath(tmpDir)
	if err := info.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Composite profile (hybrid, 2 algorithms)
	prof := &profile.Profile{
		Name:       "composite-test",
		Mode:       profile.ModeComposite,
		Algorithms: []pkicrypto.AlgorithmID{pkicrypto.AlgECDSAP384, pkicrypto.AlgMLDSA87},
		Validity:   10 * 365 * 24 * time.Hour,
	}

	newCA := &CA{}

	err := addKeyRefsToVersionMulti(tmpDir, "v2", prof, newCA)
	if err != nil {
		t.Fatalf("addKeyRefsToVersionMulti() error = %v", err)
	}

	reloaded, err := LoadCAInfo(tmpDir)
	if err != nil {
		t.Fatalf("LoadCAInfo() error = %v", err)
	}

	ver := reloaded.Versions["v2"]
	if len(ver.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(ver.Keys))
	}
}

func TestF_addKeyRefsToVersionMulti_WithKeyRefs(t *testing.T) {
	tmpDir := t.TempDir()

	info := &CAInfo{
		Subject: Subject{CommonName: "HSM CA"},
		Active:  "v1",
		Versions: map[string]CAVersion{
			"v1": {
				Profiles: []string{"test"},
				Algos:    []string{"ec"},
				Created:  time.Now(),
			},
			"v2": {
				Profiles: []string{"test"},
				Algos:    []string{"ec"},
				Created:  time.Now(),
			},
		},
	}
	info.SetBasePath(tmpDir)
	if err := info.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// CA with pre-populated keyRefs (simulates HSM initialization)
	newCA := &CA{
		keyRefs: []KeyRef{
			{
				ID:        "default",
				Algorithm: pkicrypto.AlgECDSAP384,
				Storage: pkicrypto.StorageRef{
					Type:   "pkcs11",
					Config: "hsm-config.yaml",
				},
			},
		},
	}

	prof := &profile.Profile{
		Name:      "test-ec",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}

	err := addKeyRefsToVersionMulti(tmpDir, "v2", prof, newCA)
	if err != nil {
		t.Fatalf("addKeyRefsToVersionMulti() error = %v", err)
	}

	reloaded, err := LoadCAInfo(tmpDir)
	if err != nil {
		t.Fatalf("LoadCAInfo() error = %v", err)
	}

	ver := reloaded.Versions["v2"]
	if len(ver.Keys) != 1 {
		t.Fatalf("expected 1 key from keyRefs, got %d", len(ver.Keys))
	}
	if ver.Keys[0].Storage.Type != "pkcs11" {
		t.Errorf("storage type = %q, want %q", ver.Keys[0].Storage.Type, "pkcs11")
	}
}

func TestF_addKeyRefsToVersionMulti_InvalidCADir(t *testing.T) {
	// Point to a directory without ca.meta.json
	tmpDir := t.TempDir()

	prof := &profile.Profile{
		Name:      "test",
		Algorithm: pkicrypto.AlgECDSAP256,
		Validity:  10 * 365 * 24 * time.Hour,
	}
	newCA := &CA{}

	err := addKeyRefsToVersionMulti(tmpDir, "v1", prof, newCA)
	if err == nil {
		t.Error("addKeyRefsToVersionMulti() should fail when CA info cannot be loaded")
	}
}

// =============================================================================
// Helpers
// =============================================================================

// buildCAInfoWithKeys creates a CAInfo with multiple versions for testing key lookups.
func buildCAInfoWithKeys() *CAInfo {
	now := time.Now()
	return &CAInfo{
		Active: "v1",
		Versions: map[string]CAVersion{
			"v1": {
				Algos:   []string{"ec", "ml-dsa"},
				Created: now,
				Keys: []KeyRef{
					{
						ID:        "classical",
						Algorithm: pkicrypto.AlgECDSAP384,
						Storage:   CreateSoftwareKeyRef("versions/v1/keys/ca.ecdsa-p384.key"),
					},
					{
						ID:        "pqc",
						Algorithm: pkicrypto.AlgMLDSA87,
						Storage:   CreateSoftwareKeyRef("versions/v1/keys/ca.ml-dsa-87.key"),
					},
				},
			},
			"v2": {
				Algos:   []string{"ml-dsa"},
				Created: now,
				Keys: []KeyRef{
					{
						ID:        "default",
						Algorithm: pkicrypto.AlgMLDSA65,
						Storage:   CreateSoftwareKeyRef("versions/v2/keys/ca.ml-dsa-65.key"),
					},
				},
			},
			"v3": {
				Algos:   []string{"ec"},
				Created: now,
				Keys: []KeyRef{
					{
						ID:        "default",
						Algorithm: pkicrypto.AlgECDSAP384,
						Storage:   CreateSoftwareKeyRef("versions/v3/keys/ca.ecdsa-p384.key"),
					},
				},
			},
		},
	}
}
