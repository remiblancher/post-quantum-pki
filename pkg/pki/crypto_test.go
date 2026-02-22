package pki

import (
	"testing"

	pkicrypto "github.com/remiblancher/qpki/internal/crypto"
)

// =============================================================================
// IsPostQuantumAlgorithm Tests
// =============================================================================

func TestU_IsPostQuantumAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      AlgorithmID
		expected bool
	}{
		{
			name:     "[Unit] IsPostQuantumAlgorithm: ECDSA P-256 is not PQC",
			alg:      AlgorithmID(pkicrypto.AlgECDSAP256),
			expected: false,
		},
		{
			name:     "[Unit] IsPostQuantumAlgorithm: ECDSA P-384 is not PQC",
			alg:      AlgorithmID(pkicrypto.AlgECDSAP384),
			expected: false,
		},
		{
			name:     "[Unit] IsPostQuantumAlgorithm: ML-DSA-65 is PQC",
			alg:      AlgorithmID(pkicrypto.AlgMLDSA65),
			expected: true,
		},
		{
			name:     "[Unit] IsPostQuantumAlgorithm: ML-DSA-87 is PQC",
			alg:      AlgorithmID(pkicrypto.AlgMLDSA87),
			expected: true,
		},
		{
			name:     "[Unit] IsPostQuantumAlgorithm: SLH-DSA-SHA2-128f is PQC",
			alg:      AlgorithmID(pkicrypto.AlgSLHDSASHA2128f),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPostQuantumAlgorithm(tt.alg)
			if result != tt.expected {
				t.Errorf("IsPostQuantumAlgorithm() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// IsSupportedAlgorithm Tests
// =============================================================================

func TestU_IsSupportedAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      AlgorithmID
		expected bool
	}{
		{
			name:     "[Unit] IsSupportedAlgorithm: ECDSA P-256 is supported",
			alg:      AlgorithmID(pkicrypto.AlgECDSAP256),
			expected: true,
		},
		{
			name:     "[Unit] IsSupportedAlgorithm: ML-DSA-65 is supported",
			alg:      AlgorithmID(pkicrypto.AlgMLDSA65),
			expected: true,
		},
		{
			name:     "[Unit] IsSupportedAlgorithm: empty algorithm is not supported",
			alg:      AlgorithmID(""),
			expected: false,
		},
		{
			name:     "[Unit] IsSupportedAlgorithm: unknown algorithm is not supported",
			alg:      AlgorithmID("unknown-algorithm"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSupportedAlgorithm(tt.alg)
			if result != tt.expected {
				t.Errorf("IsSupportedAlgorithm() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// IsClassicalAlgorithm Tests
// =============================================================================

func TestU_IsClassicalAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		alg      AlgorithmID
		expected bool
	}{
		{
			name:     "[Unit] IsClassicalAlgorithm: ECDSA P-256 is classical",
			alg:      AlgorithmID(pkicrypto.AlgECDSAP256),
			expected: true,
		},
		{
			name:     "[Unit] IsClassicalAlgorithm: ECDSA P-384 is classical",
			alg:      AlgorithmID(pkicrypto.AlgECDSAP384),
			expected: true,
		},
		{
			name:     "[Unit] IsClassicalAlgorithm: ML-DSA-65 is not classical",
			alg:      AlgorithmID(pkicrypto.AlgMLDSA65),
			expected: false,
		},
		{
			name:     "[Unit] IsClassicalAlgorithm: SLH-DSA is not classical",
			alg:      AlgorithmID(pkicrypto.AlgSLHDSASHA2128f),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsClassicalAlgorithm(tt.alg)
			if result != tt.expected {
				t.Errorf("IsClassicalAlgorithm() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// GenerateKeyPair Tests
// =============================================================================

func TestU_GenerateKeyPair(t *testing.T) {
	t.Run("[Unit] GenerateKeyPair: valid ECDSA P-256", func(t *testing.T) {
		kp, err := GenerateKeyPair(AlgorithmID(pkicrypto.AlgECDSAP256))
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		if kp == nil {
			t.Error("GenerateKeyPair() returned nil key pair")
		}
		if kp.PrivateKey == nil {
			t.Error("GenerateKeyPair() returned nil private key")
		}
		if kp.PublicKey == nil {
			t.Error("GenerateKeyPair() returned nil public key")
		}
	})

	t.Run("[Unit] GenerateKeyPair: valid ECDSA P-384", func(t *testing.T) {
		kp, err := GenerateKeyPair(AlgorithmID(pkicrypto.AlgECDSAP384))
		if err != nil {
			t.Fatalf("GenerateKeyPair() error = %v", err)
		}
		if kp == nil {
			t.Error("GenerateKeyPair() returned nil key pair")
		}
	})

	t.Run("[Unit] GenerateKeyPair: invalid algorithm", func(t *testing.T) {
		_, err := GenerateKeyPair(AlgorithmID("invalid"))
		if err == nil {
			t.Error("GenerateKeyPair() should fail for invalid algorithm")
		}
	})
}

// =============================================================================
// LoadPrivateKey Tests
// =============================================================================

func TestU_LoadPrivateKey(t *testing.T) {
	t.Run("[Unit] LoadPrivateKey: file not found", func(t *testing.T) {
		_, err := LoadPrivateKey("/nonexistent/path/key.pem", nil)
		if err == nil {
			t.Error("LoadPrivateKey() should fail for non-existent file")
		}
	})
}

// =============================================================================
// LoadHSMConfig Tests
// =============================================================================

func TestU_LoadHSMConfig(t *testing.T) {
	t.Run("[Unit] LoadHSMConfig: file not found", func(t *testing.T) {
		_, err := LoadHSMConfig("/nonexistent/path/hsm.yaml")
		if err == nil {
			t.Error("LoadHSMConfig() should fail for non-existent file")
		}
	})
}

// =============================================================================
// GenerateHybridKeyPair Tests
// =============================================================================

func TestU_GenerateHybridKeyPair(t *testing.T) {
	t.Run("[Unit] GenerateHybridKeyPair: Hybrid P-256 + ML-DSA-44", func(t *testing.T) {
		kp, err := GenerateHybridKeyPair(AlgorithmID(pkicrypto.AlgHybridP256MLDSA44))
		if err != nil {
			t.Fatalf("GenerateHybridKeyPair() error = %v", err)
		}
		if kp == nil {
			t.Error("GenerateHybridKeyPair() returned nil")
		}
	})

	t.Run("[Unit] GenerateHybridKeyPair: Hybrid P-384 + ML-DSA-65", func(t *testing.T) {
		kp, err := GenerateHybridKeyPair(AlgorithmID(pkicrypto.AlgHybridP384MLDSA65))
		if err != nil {
			t.Fatalf("GenerateHybridKeyPair() error = %v", err)
		}
		if kp == nil {
			t.Error("GenerateHybridKeyPair() returned nil")
		}
	})

	t.Run("[Unit] GenerateHybridKeyPair: invalid algorithm", func(t *testing.T) {
		_, err := GenerateHybridKeyPair(AlgorithmID("invalid"))
		if err == nil {
			t.Error("GenerateHybridKeyPair() should fail for invalid algorithm")
		}
	})

	t.Run("[Unit] GenerateHybridKeyPair: non-hybrid algorithm", func(t *testing.T) {
		_, err := GenerateHybridKeyPair(AlgorithmID(pkicrypto.AlgMLDSA65))
		if err == nil {
			t.Error("GenerateHybridKeyPair() should fail for non-hybrid algorithm")
		}
	})
}

// =============================================================================
// GenerateKEMKeyPair Tests
// =============================================================================

func TestU_GenerateKEMKeyPair(t *testing.T) {
	t.Run("[Unit] GenerateKEMKeyPair: ML-KEM-768", func(t *testing.T) {
		kp, err := GenerateKEMKeyPair(AlgorithmID(pkicrypto.AlgMLKEM768))
		if err != nil {
			t.Fatalf("GenerateKEMKeyPair() error = %v", err)
		}
		if kp == nil {
			t.Error("GenerateKEMKeyPair() returned nil")
		}
	})

	t.Run("[Unit] GenerateKEMKeyPair: invalid algorithm", func(t *testing.T) {
		_, err := GenerateKEMKeyPair(AlgorithmID("invalid"))
		if err == nil {
			t.Error("GenerateKEMKeyPair() should fail for invalid algorithm")
		}
	})
}

// =============================================================================
// CryptoLoadPrivateKey Tests (alias)
// =============================================================================

func TestU_CryptoLoadPrivateKey(t *testing.T) {
	t.Run("[Unit] CryptoLoadPrivateKey: file not found", func(t *testing.T) {
		_, err := CryptoLoadPrivateKey("/nonexistent/key.pem", nil)
		if err == nil {
			t.Error("CryptoLoadPrivateKey() should fail for non-existent file")
		}
	})
}

// =============================================================================
// GenerateKeyPair for PQC algorithms
// =============================================================================

func TestU_GenerateKeyPair_PQC(t *testing.T) {
	t.Run("[Unit] GenerateKeyPair: ML-DSA-65", func(t *testing.T) {
		kp, err := GenerateKeyPair(AlgorithmID(pkicrypto.AlgMLDSA65))
		if err != nil {
			t.Fatalf("GenerateKeyPair(ML-DSA-65) error = %v", err)
		}
		if kp == nil {
			t.Error("GenerateKeyPair(ML-DSA-65) returned nil")
		}
	})

	t.Run("[Unit] GenerateKeyPair: ML-DSA-87", func(t *testing.T) {
		kp, err := GenerateKeyPair(AlgorithmID(pkicrypto.AlgMLDSA87))
		if err != nil {
			t.Fatalf("GenerateKeyPair(ML-DSA-87) error = %v", err)
		}
		if kp == nil {
			t.Error("GenerateKeyPair(ML-DSA-87) returned nil")
		}
	})

	t.Run("[Unit] GenerateKeyPair: SLH-DSA-SHA2-128f", func(t *testing.T) {
		kp, err := GenerateKeyPair(AlgorithmID(pkicrypto.AlgSLHDSASHA2128f))
		if err != nil {
			t.Fatalf("GenerateKeyPair(SLH-DSA) error = %v", err)
		}
		if kp == nil {
			t.Error("GenerateKeyPair(SLH-DSA) returned nil")
		}
	})
}
