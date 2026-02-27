// Package cose implements COSE (RFC 9052) and CWT (RFC 8392) signing and verification.
// It supports classical, post-quantum, and hybrid cryptographic algorithms.
package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
	gocose "github.com/veraison/go-cose"

	pkicrypto "github.com/remiblancher/qpki/internal/crypto"
)

// COSE Algorithm IDs.
// Classical algorithms are from IANA COSE Algorithms Registry.
// PQC algorithms follow draft-ietf-cose-dilithium-04 for ML-DSA
// and use private-use range for SLH-DSA.
const (
	// Classical algorithms (IANA registered)
	AlgES256 gocose.Algorithm = -7  // ECDSA w/ SHA-256
	AlgES384 gocose.Algorithm = -35 // ECDSA w/ SHA-384
	AlgES512 gocose.Algorithm = -36 // ECDSA w/ SHA-512
	AlgEdDSA gocose.Algorithm = -8  // EdDSA (Ed25519/Ed448)
	AlgPS256 gocose.Algorithm = -37 // RSASSA-PSS w/ SHA-256
	AlgPS384 gocose.Algorithm = -38 // RSASSA-PSS w/ SHA-384
	AlgPS512 gocose.Algorithm = -39 // RSASSA-PSS w/ SHA-512

	// ML-DSA algorithms (draft-ietf-cose-dilithium-04)
	AlgMLDSA44 gocose.Algorithm = -48
	AlgMLDSA65 gocose.Algorithm = -49
	AlgMLDSA87 gocose.Algorithm = -50

	// SLH-DSA algorithms (private-use range, no IETF draft yet)
	// Using -70020 to -70031 for SHA2 and SHAKE variants
	AlgSLHDSASHA2128s  gocose.Algorithm = -70020
	AlgSLHDSASHA2128f  gocose.Algorithm = -70021
	AlgSLHDSASHA2192s  gocose.Algorithm = -70022
	AlgSLHDSASHA2192f  gocose.Algorithm = -70023
	AlgSLHDSASHA2256s  gocose.Algorithm = -70024
	AlgSLHDSASHA2256f  gocose.Algorithm = -70025
	AlgSLHDSASHAKE128s gocose.Algorithm = -70026
	AlgSLHDSASHAKE128f gocose.Algorithm = -70027
	AlgSLHDSASHAKE192s gocose.Algorithm = -70028
	AlgSLHDSASHAKE192f gocose.Algorithm = -70029
	AlgSLHDSASHAKE256s gocose.Algorithm = -70030
	AlgSLHDSASHAKE256f gocose.Algorithm = -70031
)

// pkiToCOSEMap maps pkicrypto.AlgorithmID to COSE Algorithm.
// Using a map reduces cyclomatic complexity compared to a switch statement.
var pkiToCOSEMap = map[pkicrypto.AlgorithmID]gocose.Algorithm{
	// ECDSA
	pkicrypto.AlgECDSAP256: AlgES256,
	pkicrypto.AlgECP256:    AlgES256,
	pkicrypto.AlgECDSAP384: AlgES384,
	pkicrypto.AlgECP384:    AlgES384,
	pkicrypto.AlgECDSAP521: AlgES512,
	pkicrypto.AlgECP521:    AlgES512,
	// EdDSA
	pkicrypto.AlgEd25519: AlgEdDSA,
	pkicrypto.AlgEd448:   AlgEdDSA,
	// RSA
	pkicrypto.AlgRSA2048: AlgPS256,
	pkicrypto.AlgRSA4096: AlgPS256,
	// ML-DSA
	pkicrypto.AlgMLDSA44: AlgMLDSA44,
	pkicrypto.AlgMLDSA65: AlgMLDSA65,
	pkicrypto.AlgMLDSA87: AlgMLDSA87,
	// SLH-DSA SHA2
	pkicrypto.AlgSLHDSASHA2128s: AlgSLHDSASHA2128s,
	pkicrypto.AlgSLHDSASHA2128f: AlgSLHDSASHA2128f,
	pkicrypto.AlgSLHDSASHA2192s: AlgSLHDSASHA2192s,
	pkicrypto.AlgSLHDSASHA2192f: AlgSLHDSASHA2192f,
	pkicrypto.AlgSLHDSASHA2256s: AlgSLHDSASHA2256s,
	pkicrypto.AlgSLHDSASHA2256f: AlgSLHDSASHA2256f,
	// SLH-DSA SHAKE
	pkicrypto.AlgSLHDSASHAKE128s: AlgSLHDSASHAKE128s,
	pkicrypto.AlgSLHDSASHAKE128f: AlgSLHDSASHAKE128f,
	pkicrypto.AlgSLHDSASHAKE192s: AlgSLHDSASHAKE192s,
	pkicrypto.AlgSLHDSASHAKE192f: AlgSLHDSASHAKE192f,
	pkicrypto.AlgSLHDSASHAKE256s: AlgSLHDSASHAKE256s,
	pkicrypto.AlgSLHDSASHAKE256f: AlgSLHDSASHAKE256f,
}

// COSEAlgorithmFromPKI converts a pkicrypto.AlgorithmID to a COSE Algorithm.
func COSEAlgorithmFromPKI(alg pkicrypto.AlgorithmID) (gocose.Algorithm, error) {
	if coseAlg, ok := pkiToCOSEMap[alg]; ok {
		return coseAlg, nil
	}
	return 0, fmt.Errorf("unsupported algorithm for COSE: %s", alg)
}

// coseToPKIMap maps COSE Algorithm to pkicrypto.AlgorithmID.
// Note: Some COSE algorithms map to a default PKI variant (e.g., EdDSA -> Ed25519, PS* -> RSA-4096).
var coseToPKIMap = map[gocose.Algorithm]pkicrypto.AlgorithmID{
	// Classical
	AlgES256: pkicrypto.AlgECDSAP256,
	AlgES384: pkicrypto.AlgECDSAP384,
	AlgES512: pkicrypto.AlgECDSAP521,
	AlgEdDSA: pkicrypto.AlgEd25519, // Default to Ed25519
	AlgPS256: pkicrypto.AlgRSA4096, // Default to RSA-4096
	AlgPS384: pkicrypto.AlgRSA4096,
	AlgPS512: pkicrypto.AlgRSA4096,
	// ML-DSA
	AlgMLDSA44: pkicrypto.AlgMLDSA44,
	AlgMLDSA65: pkicrypto.AlgMLDSA65,
	AlgMLDSA87: pkicrypto.AlgMLDSA87,
	// SLH-DSA SHA2
	AlgSLHDSASHA2128s: pkicrypto.AlgSLHDSASHA2128s,
	AlgSLHDSASHA2128f: pkicrypto.AlgSLHDSASHA2128f,
	AlgSLHDSASHA2192s: pkicrypto.AlgSLHDSASHA2192s,
	AlgSLHDSASHA2192f: pkicrypto.AlgSLHDSASHA2192f,
	AlgSLHDSASHA2256s: pkicrypto.AlgSLHDSASHA2256s,
	AlgSLHDSASHA2256f: pkicrypto.AlgSLHDSASHA2256f,
	// SLH-DSA SHAKE
	AlgSLHDSASHAKE128s: pkicrypto.AlgSLHDSASHAKE128s,
	AlgSLHDSASHAKE128f: pkicrypto.AlgSLHDSASHAKE128f,
	AlgSLHDSASHAKE192s: pkicrypto.AlgSLHDSASHAKE192s,
	AlgSLHDSASHAKE192f: pkicrypto.AlgSLHDSASHAKE192f,
	AlgSLHDSASHAKE256s: pkicrypto.AlgSLHDSASHAKE256s,
	AlgSLHDSASHAKE256f: pkicrypto.AlgSLHDSASHAKE256f,
}

// PKIAlgorithmFromCOSE converts a COSE Algorithm to a pkicrypto.AlgorithmID.
// Note: This may return a default variant when multiple PKI algorithms map to the same COSE algorithm.
func PKIAlgorithmFromCOSE(alg gocose.Algorithm) (pkicrypto.AlgorithmID, error) {
	if pkiAlg, ok := coseToPKIMap[alg]; ok {
		return pkiAlg, nil
	}
	return "", fmt.Errorf("unsupported COSE algorithm: %d", alg)
}

// COSEAlgorithmFromKey determines the COSE algorithm from a public key.
func COSEAlgorithmFromKey(key crypto.PublicKey) (gocose.Algorithm, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return AlgES256, nil
		case 384:
			return AlgES384, nil
		case 521:
			return AlgES512, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve size: %d", k.Curve.Params().BitSize)
		}
	case ed25519.PublicKey:
		return AlgEdDSA, nil
	case *rsa.PublicKey:
		return AlgPS256, nil // Default to PS256 for RSA
	// ML-DSA (circl library types)
	case *mldsa44.PublicKey:
		return AlgMLDSA44, nil
	case *mldsa65.PublicKey:
		return AlgMLDSA65, nil
	case *mldsa87.PublicKey:
		return AlgMLDSA87, nil
	// ML-DSA (HSM wrapper type)
	case *pkicrypto.MLDSAPublicKey:
		return COSEAlgorithmFromPKI(k.Algorithm)
	// SLH-DSA
	case *slhdsa.PublicKey:
		return algorithmFromSLHDSAKey(k)
	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}

// algorithmFromSLHDSAKey determines the COSE algorithm from an SLH-DSA public key.
func algorithmFromSLHDSAKey(key *slhdsa.PublicKey) (gocose.Algorithm, error) {
	// SLH-DSA keys have an ID field that identifies the algorithm variant
	switch key.ID {
	// SHA2 variants
	case slhdsa.SHA2_128s:
		return AlgSLHDSASHA2128s, nil
	case slhdsa.SHA2_128f:
		return AlgSLHDSASHA2128f, nil
	case slhdsa.SHA2_192s:
		return AlgSLHDSASHA2192s, nil
	case slhdsa.SHA2_192f:
		return AlgSLHDSASHA2192f, nil
	case slhdsa.SHA2_256s:
		return AlgSLHDSASHA2256s, nil
	case slhdsa.SHA2_256f:
		return AlgSLHDSASHA2256f, nil
	// SHAKE variants
	case slhdsa.SHAKE_128s:
		return AlgSLHDSASHAKE128s, nil
	case slhdsa.SHAKE_128f:
		return AlgSLHDSASHAKE128f, nil
	case slhdsa.SHAKE_192s:
		return AlgSLHDSASHAKE192s, nil
	case slhdsa.SHAKE_192f:
		return AlgSLHDSASHAKE192f, nil
	case slhdsa.SHAKE_256s:
		return AlgSLHDSASHAKE256s, nil
	case slhdsa.SHAKE_256f:
		return AlgSLHDSASHAKE256f, nil
	default:
		return 0, fmt.Errorf("unsupported SLH-DSA ID: %v", key.ID)
	}
}

// algorithmNameMap maps COSE Algorithm IDs to human-readable names.
var algorithmNameMap = map[gocose.Algorithm]string{
	AlgES256:           "ES256",
	AlgES384:           "ES384",
	AlgES512:           "ES512",
	AlgEdDSA:           "EdDSA",
	AlgPS256:           "PS256",
	AlgPS384:           "PS384",
	AlgPS512:           "PS512",
	AlgMLDSA44:         "ML-DSA-44",
	AlgMLDSA65:         "ML-DSA-65",
	AlgMLDSA87:         "ML-DSA-87",
	AlgSLHDSASHA2128s:  "SLH-DSA-SHA2-128s",
	AlgSLHDSASHA2128f:  "SLH-DSA-SHA2-128f",
	AlgSLHDSASHA2192s:  "SLH-DSA-SHA2-192s",
	AlgSLHDSASHA2192f:  "SLH-DSA-SHA2-192f",
	AlgSLHDSASHA2256s:  "SLH-DSA-SHA2-256s",
	AlgSLHDSASHA2256f:  "SLH-DSA-SHA2-256f",
	AlgSLHDSASHAKE128s: "SLH-DSA-SHAKE-128s",
	AlgSLHDSASHAKE128f: "SLH-DSA-SHAKE-128f",
	AlgSLHDSASHAKE192s: "SLH-DSA-SHAKE-192s",
	AlgSLHDSASHAKE192f: "SLH-DSA-SHAKE-192f",
	AlgSLHDSASHAKE256s: "SLH-DSA-SHAKE-256s",
	AlgSLHDSASHAKE256f: "SLH-DSA-SHAKE-256f",
}

// AlgorithmName returns a human-readable name for a COSE algorithm.
func AlgorithmName(alg gocose.Algorithm) string {
	if name, ok := algorithmNameMap[alg]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", alg)
}

// IsPQCAlgorithm returns true if the COSE algorithm is post-quantum.
func IsPQCAlgorithm(alg gocose.Algorithm) bool {
	switch alg {
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87,
		AlgSLHDSASHA2128s, AlgSLHDSASHA2128f,
		AlgSLHDSASHA2192s, AlgSLHDSASHA2192f,
		AlgSLHDSASHA2256s, AlgSLHDSASHA2256f,
		AlgSLHDSASHAKE128s, AlgSLHDSASHAKE128f,
		AlgSLHDSASHAKE192s, AlgSLHDSASHAKE192f,
		AlgSLHDSASHAKE256s, AlgSLHDSASHAKE256f:
		return true
	default:
		return false
	}
}

// IsClassicalAlgorithm returns true if the COSE algorithm is classical (non-PQC).
func IsClassicalAlgorithm(alg gocose.Algorithm) bool {
	switch alg {
	case AlgES256, AlgES384, AlgES512, AlgEdDSA, AlgPS256, AlgPS384, AlgPS512:
		return true
	default:
		return false
	}
}
