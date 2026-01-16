package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
)

// ctx is the default context for CA operations.
var ctx = context.Background()

// profileAlgorithmInfo holds algorithm information extracted from a profile.
type profileAlgorithmInfo struct {
	Algorithm      crypto.AlgorithmID
	HybridAlg      crypto.AlgorithmID
	IsComposite    bool
	IsCatalyst     bool
	ValidityYears  int
	PathLen        int
}

// extractProfileAlgorithmInfo extracts algorithm information from a profile.
func extractProfileAlgorithmInfo(prof *profile.Profile) (*profileAlgorithmInfo, error) {
	info := &profileAlgorithmInfo{}

	// Extract algorithm from profile
	info.Algorithm = prof.GetAlgorithm()
	if !info.Algorithm.IsValid() {
		return nil, fmt.Errorf("profile has invalid algorithm: %s", info.Algorithm)
	}

	// Extract hybrid algorithm if profile is Catalyst or Composite
	if prof.IsCatalyst() {
		info.HybridAlg = prof.GetAlternativeAlgorithm()
		info.IsCatalyst = true
	} else if prof.IsComposite() {
		info.HybridAlg = prof.GetAlternativeAlgorithm()
		info.IsComposite = true
	}

	// Extract validity (convert from duration to years)
	info.ValidityYears = int(prof.Validity.Hours() / 24 / 365)
	if info.ValidityYears < 1 {
		info.ValidityYears = 1
	}

	// Extract pathLen from profile extensions
	info.PathLen = 1 // default
	if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
		info.PathLen = *prof.Extensions.BasicConstraints.PathLen
	}

	return info, nil
}

// loadAndValidateProfileVariables loads and validates variables for a profile.
func loadAndValidateProfileVariables(prof *profile.Profile, varFile string, vars []string) (profile.VariableValues, error) {
	varValues, err := profile.LoadVariables(varFile, vars)
	if err != nil {
		return nil, fmt.Errorf("failed to load variables: %w", err)
	}

	// Validate variables against profile constraints
	if len(prof.Variables) > 0 {
		engine, err := profile.NewTemplateEngine(prof)
		if err != nil {
			return nil, fmt.Errorf("failed to create template engine: %w", err)
		}
		rendered, err := engine.Render(varValues)
		if err != nil {
			return nil, fmt.Errorf("failed to validate variables: %w", err)
		}
		varValues = rendered.ResolvedValues
	}

	return varValues, nil
}

// buildCAConfigFromProfile builds a CA configuration from a profile and variables.
func buildCAConfigFromProfile(
	prof *profile.Profile,
	subject pkix.Name,
	algInfo *profileAlgorithmInfo,
	passphrase string,
) (*ca.Config, error) {
	cfg := &ca.Config{
		CommonName:    subject.CommonName,
		Organization:  firstOrEmpty(subject.Organization),
		Country:       firstOrEmpty(subject.Country),
		Algorithm:     algInfo.Algorithm,
		ValidityYears: algInfo.ValidityYears,
		PathLen:       algInfo.PathLen,
		Passphrase:    passphrase,
		Extensions:    prof.Extensions,
	}

	// Configure hybrid if requested
	if algInfo.HybridAlg != "" {
		if !algInfo.HybridAlg.IsPQC() {
			return nil, fmt.Errorf("hybrid algorithm must be a PQC algorithm, got: %s", algInfo.HybridAlg)
		}
		cfg.HybridConfig = &ca.HybridConfig{
			Algorithm: algInfo.HybridAlg,
			Policy:    0, // HybridPolicyInformational
		}
	}

	return cfg, nil
}

// initializeCAByType initializes a CA based on its type (composite, hybrid, PQC, or classical).
func initializeCAByType(store *ca.FileStore, cfg *ca.Config, isComposite bool) (*ca.CA, error) {
	if isComposite && cfg.HybridConfig != nil {
		// Use InitializeCompositeCA for IETF composite signatures
		compositeCfg := ca.CompositeCAConfig{
			CommonName:         cfg.CommonName,
			Organization:       cfg.Organization,
			Country:            cfg.Country,
			ClassicalAlgorithm: cfg.Algorithm,
			PQCAlgorithm:       cfg.HybridConfig.Algorithm,
			ValidityYears:      cfg.ValidityYears,
			PathLen:            cfg.PathLen,
			Passphrase:         cfg.Passphrase,
		}
		return ca.InitializeCompositeCA(store, compositeCfg)
	}

	if cfg.HybridConfig != nil {
		// Use InitializeHybridCA for Catalyst mode (PQC in extension)
		hybridCfg := ca.HybridCAConfig{
			CommonName:         cfg.CommonName,
			Organization:       cfg.Organization,
			Country:            cfg.Country,
			ClassicalAlgorithm: cfg.Algorithm,
			PQCAlgorithm:       cfg.HybridConfig.Algorithm,
			ValidityYears:      cfg.ValidityYears,
			PathLen:            cfg.PathLen,
			Passphrase:         cfg.Passphrase,
		}
		return ca.InitializeHybridCA(store, hybridCfg)
	}

	if cfg.Algorithm.IsPQC() {
		// Use InitializePQCCA for pure PQC certificates (manual DER construction)
		pqcCfg := ca.PQCCAConfig{
			CommonName:    cfg.CommonName,
			Organization:  cfg.Organization,
			Country:       cfg.Country,
			Algorithm:     cfg.Algorithm,
			ValidityYears: cfg.ValidityYears,
			PathLen:       cfg.PathLen,
			Passphrase:    cfg.Passphrase,
		}
		return ca.InitializePQCCA(store, pqcCfg)
	}

	return ca.Initialize(store, *cfg)
}

// printCAInitSuccess prints the success message after CA initialization.
func printCAInitSuccess(newCA *ca.CA, absDir string, cfg *ca.Config, isComposite bool) {
	cert := newCA.Certificate()

	// Load CAInfo to get the versioned cert path
	info, _ := ca.LoadCAInfo(absDir)
	var certPath string
	if info != nil && info.Active != "" {
		activeVer := info.ActiveVersion()
		if activeVer != nil && len(activeVer.Algos) > 0 {
			certPath = info.CertPath(info.Active, activeVer.Algos[0])
		}
	}
	if certPath == "" {
		certPath = newCA.Store().CACertPath()
	}

	fmt.Printf("\nCA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Serial:      %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate: %s\n", certPath)
	fmt.Printf("  Private Key: %s\n", newCA.DefaultKeyPath())

	if cfg.HybridConfig != nil {
		if isComposite {
			fmt.Printf("  Mode:        Composite (IETF)\n")
		} else {
			fmt.Printf("  Mode:        Catalyst (ITU-T)\n")
		}
		fmt.Printf("  PQC Key:     %s.pqc\n", newCA.DefaultKeyPath())
	}

	if cfg.Passphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private key is not encrypted. Use --passphrase for production.\n")
	}
}

// exportCertsResult holds the result of exporting certificates.
type exportCertsResult struct {
	Certificates []*x509.Certificate
	Format       string
}

// encodeCertificates encodes certificates to PEM or DER format.
func encodeCertificates(certs []*x509.Certificate, format string) ([]byte, error) {
	if format == "der" {
		if len(certs) > 1 {
			return nil, fmt.Errorf("DER format only supports single certificate, use PEM for chain")
		}
		return certs[0].Raw, nil
	}

	// PEM format
	var output []byte
	for _, cert := range certs {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		output = append(output, pem.EncodeToMemory(block)...)
	}
	return output, nil
}

// writeExportOutput writes exported certificates to file or stdout.
func writeExportOutput(data []byte, outputPath string, certCount int) error {
	if outputPath == "" {
		fmt.Print(string(data))
		return nil
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	fmt.Printf("Exported %d certificate(s) to %s\n", certCount, outputPath)
	return nil
}

// loadAllVersionCerts loads certificates from all versions when --all flag is used.
func loadAllVersionCerts(absDir string, info *ca.CAInfo) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	if info == nil || len(info.Versions) == 0 {
		// Not versioned, just export the current CA
		store := ca.NewFileStore(absDir)
		if !store.Exists() {
			return nil, fmt.Errorf("CA not found at %s", absDir)
		}
		caCert, err := store.LoadCACert(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}
		return []*x509.Certificate{caCert}, nil
	}

	// Export all versions using CAInfo
	info.SetBasePath(absDir)
	for versionID, ver := range info.Versions {
		for _, algo := range ver.Algos {
			certPath := info.CertPath(versionID, algo)
			if cert, err := loadCertFromPath(certPath); err == nil {
				certs = append(certs, cert)
			}
		}
	}
	return certs, nil
}

// loadVersionCerts loads certificates for a specific version.
func loadVersionCerts(absDir, versionID string, info *ca.CAInfo) ([]*x509.Certificate, error) {
	if info == nil || len(info.Versions) == 0 {
		return nil, fmt.Errorf("CA is not versioned, cannot use --version flag")
	}

	info.SetBasePath(absDir)
	ver, ok := info.Versions[versionID]
	if !ok {
		return nil, fmt.Errorf("version %s not found", versionID)
	}

	var certs []*x509.Certificate
	for _, algo := range ver.Algos {
		certPath := info.CertPath(versionID, algo)
		if cert, err := loadCertFromPath(certPath); err == nil {
			certs = append(certs, cert)
		}
	}

	// Fallback: check legacy ca.crt path (for rotate-created versions)
	if len(certs) == 0 {
		legacyCertPath := filepath.Join(absDir, "versions", versionID, "ca.crt")
		if cert, err := loadCertFromPath(legacyCertPath); err == nil {
			certs = append(certs, cert)
		}
	}

	return certs, nil
}

// validateHSMFlags validates HSM-related command flags.
func validateHSMFlags(generateKey bool, keyLabel, keyID string) error {
	if generateKey {
		if keyLabel == "" {
			return fmt.Errorf("--key-label is required when using --generate-key")
		}
	} else {
		if keyLabel == "" && keyID == "" {
			return fmt.Errorf("--key-label or --key-id is required when using --hsm-config (or use --generate-key)")
		}
	}
	return nil
}

// validateHSMProfile validates that a profile is compatible with HSM.
func validateHSMProfile(prof *profile.Profile, alg crypto.AlgorithmID, profileName string) error {
	if alg.IsPQC() {
		return fmt.Errorf("HSM does not support PQC algorithms. Use a classical profile (ec/*, rsa/*) or remove --hsm-config")
	}
	if prof.IsCatalyst() || prof.IsComposite() {
		return fmt.Errorf("HSM does not support hybrid/composite profiles. Use a classical profile (ec/*, rsa/*) or remove --hsm-config")
	}
	return nil
}

// generateHSMKey generates a key in the HSM if requested.
func generateHSMKey(hsmCfg *crypto.HSMConfig, alg crypto.AlgorithmID, keyLabel string) (string, string, error) {
	pin, err := hsmCfg.GetPIN()
	if err != nil {
		return "", "", fmt.Errorf("failed to get PIN: %w", err)
	}

	fmt.Printf("Generating %s key in HSM...\n", alg)
	genCfg := crypto.GenerateHSMKeyPairConfig{
		ModulePath: hsmCfg.PKCS11.Lib,
		TokenLabel: hsmCfg.PKCS11.Token,
		PIN:        pin,
		KeyLabel:   keyLabel,
		Algorithm:  alg,
	}

	result, err := crypto.GenerateHSMKeyPair(genCfg)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key in HSM: %w", err)
	}

	fmt.Printf("  Key generated: label=%s, id=%s\n", result.KeyLabel, result.KeyID)
	return result.KeyLabel, result.KeyID, nil
}

// loadBundleCerts loads certificates based on bundle type (ca, chain, root).
func loadBundleCerts(store ca.Store, bundleType string) ([]*x509.Certificate, error) {
	caCert, err := store.LoadCACert(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	switch bundleType {
	case "ca":
		return []*x509.Certificate{caCert}, nil

	case "chain":
		certs := []*x509.Certificate{caCert}
		// Load cross-signed certificates (for CA rotation scenarios)
		if crossCerts, err := store.LoadCrossSignedCerts(ctx); err == nil && len(crossCerts) > 0 {
			certs = append(certs, crossCerts...)
		}
		// Try to load chain file (parent CA for subordinate CAs)
		chainPath := filepath.Join(store.BasePath(), "chain.crt")
		if chainData, err := os.ReadFile(chainPath); err == nil {
			if chainCerts, err := parseCertificatesPEM(chainData); err == nil {
				// Skip the first cert (it's the CA cert already added)
				for i, c := range chainCerts {
					if i > 0 {
						certs = append(certs, c)
					}
				}
			}
		}
		return certs, nil

	case "root":
		chainPath := filepath.Join(store.BasePath(), "chain.crt")
		if chainData, err := os.ReadFile(chainPath); err == nil {
			if chainCerts, err := parseCertificatesPEM(chainData); err == nil && len(chainCerts) > 0 {
				// Last cert in chain is the root
				return []*x509.Certificate{chainCerts[len(chainCerts)-1]}, nil
			}
		}
		// No chain file, CA is probably the root
		return []*x509.Certificate{caCert}, nil

	default:
		return nil, fmt.Errorf("invalid bundle type: %s (use: ca, chain, root)", bundleType)
	}
}
