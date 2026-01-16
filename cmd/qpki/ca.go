package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/post-quantum-pki/internal/ca"
	"github.com/remiblancher/post-quantum-pki/internal/crypto"
	"github.com/remiblancher/post-quantum-pki/internal/profile"
	"github.com/remiblancher/post-quantum-pki/internal/x509util"
)

// caCmd is the parent command for CA operations.
var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Certificate Authority management",
	Long: `Manage Certificate Authorities.

Commands:
  init    Initialize a new CA (root or subordinate)
  info    Display CA information

Examples:
  # Create a root CA
  pki ca init --profile ec/root-ca --ca-dir ./root-ca --var cn="My Root CA"

  # Create a subordinate CA
  pki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca --parent ./root-ca --var cn="Issuing CA"

  # Show CA information
  pki ca info --ca-dir ./root-ca`,
}

var caInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new Certificate Authority",
	Long: `Initialize a new Certificate Authority.

Creates a CA using a certificate profile that defines the algorithm, validity,
and extensions. With --parent, creates a subordinate CA signed by the parent.

The CA will be created in the specified directory with the following structure:
  {dir}/
    ├── ca.crt           # CA certificate (PEM)
    ├── chain.crt        # Certificate chain (subordinate CA only)
    ├── private/
    │   └── ca.key       # CA private key (PEM, optionally encrypted)
    ├── certs/           # Issued certificates
    ├── crl/             # Certificate Revocation Lists
    ├── index.txt        # Certificate database
    └── serial           # Serial number counter

Available profiles (use 'pki profile list' to see all):
  ec/root-ca                   ECDSA P-384 root CA
  ec/issuing-ca                ECDSA P-384 issuing CA
  ml-dsa/root-ca               ML-DSA-65 (PQC) root CA
  hybrid/catalyst/root-ca      ECDSA + ML-DSA catalyst root CA

HSM Support:
  Use --hsm-config with --key-label to initialize a CA using an existing
  key stored in a Hardware Security Module (HSM) via PKCS#11.
  Use --generate-key to generate a new key in the HSM during initialization.
  Note: HSM mode only supports classical profiles (ec/*, rsa/*).

Variables:
  Certificate subject fields are passed via --var or --var-file:
    cn           Common Name (required)
    organization Organization name
    country      Country code (2 letters, e.g., FR, US)
    ou           Organizational Unit
    state        State or Province
    locality     Locality/City

  Use 'pki profile vars <profile>' to see all available variables.

Examples:
  # Create a root CA with ECDSA
  pki ca init --profile ec/root-ca --ca-dir ./root-ca --var cn="My Root CA"

  # Create a root CA with full subject
  pki ca init --profile ec/root-ca --ca-dir ./root-ca \
    --var cn="My Root CA" --var organization="ACME Corp" --var country=FR

  # Create a root CA using a variables file
  pki ca init --profile ec/root-ca --ca-dir ./root-ca --var-file ca-vars.yaml

  # Create a PQC root CA with ML-DSA-65
  pki ca init --profile ml-dsa/root-ca --ca-dir ./pqc-ca --var cn="PQC Root CA"

  # Create a hybrid (catalyst) root CA
  pki ca init --profile hybrid/catalyst/root-ca --ca-dir ./hybrid-ca --var cn="Hybrid Root CA"

  # Create a subordinate CA signed by the root
  pki ca init --profile ec/issuing-ca --ca-dir ./issuing-ca --parent ./root-ca --var cn="Issuing CA"

  # Protect private key with a passphrase
  pki ca init --profile ec/root-ca --passphrase "secret" --ca-dir ./ca --var cn="My CA"

  # Create a CA using an existing HSM key
  export HSM_PIN="****"
  pki ca init --profile ec/root-ca --ca-dir ./hsm-ca \
    --hsm-config ./hsm.yaml --key-label "root-ca-key" --var cn="HSM Root CA"

  # Create a CA and generate the key in HSM
  export HSM_PIN="****"
  pki ca init --profile ec/root-ca --ca-dir ./hsm-ca \
    --hsm-config ./hsm.yaml --key-label "new-root-key" --generate-key --var cn="HSM Root CA"`,
	RunE: runCAInit,
}

var caInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display CA information",
	Long:  `Display detailed information about a Certificate Authority.`,
	RunE:  runCAInfo,
}

var caExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export CA certificates",
	Long: `Export CA certificate chain in various formats.

Bundle types:
  ca      - CA certificate only (default)
  chain   - Full certificate chain (CA + parents)
  root    - Root CA certificate only

Examples:
  # Export CA certificate
  pki ca export --ca-dir ./issuing-ca

  # Export full chain to file
  pki ca export --ca-dir ./issuing-ca --bundle chain -o chain.pem

  # Export root only
  pki ca export --ca-dir ./issuing-ca --bundle root -o root.pem

  # Export specific version (for versioned CAs)
  pki ca export --ca-dir ./issuing-ca --version v20240101_abc123 -o v1.pem`,
	RunE: runCAExport,
}

var caListCmd = &cobra.Command{
	Use:   "list",
	Short: "List Certificate Authorities",
	Long: `List all Certificate Authorities in a directory.

Scans subdirectories for CA structures (directories containing ca.crt).

Examples:
  # List CAs in current directory
  pki ca list

  # List CAs in specific directory
  pki ca list --dir ./pki/cas`,
	RunE: runCAList,
}

var (
	caExportDir     string
	caExportBundle  string
	caExportOut     string
	caExportFormat  string
	caExportVersion string
	caExportAll     bool

	caListDir string
)

var (
	caInitDir              string
	caInitVars             []string // --var key=value
	caInitVarFile          string   // --var-file vars.yaml
	caInitValidityYears    int
	caInitPathLen          int
	caInitPassphrase       string
	caInitParentDir        string
	caInitParentPassphrase string
	caInitProfiles         []string // --profile (repeatable)

	// HSM-related flags (only for ca init)
	caInitHSMConfig   string
	caInitKeyLabel    string
	caInitKeyID       string
	caInitGenerateKey bool

	caInfoDir string
)

func init() {
	// Add subcommands
	caCmd.AddCommand(caInitCmd)
	caCmd.AddCommand(caInfoCmd)
	caCmd.AddCommand(caExportCmd)
	caCmd.AddCommand(caListCmd)

	// Export flags
	caExportCmd.Flags().StringVarP(&caExportDir, "ca-dir", "d", "./ca", "CA directory")
	caExportCmd.Flags().StringVarP(&caExportBundle, "bundle", "b", "ca", "Bundle type: ca, chain, root")
	caExportCmd.Flags().StringVarP(&caExportOut, "out", "o", "", "Output file (default: stdout)")
	caExportCmd.Flags().StringVarP(&caExportFormat, "format", "f", "pem", "Output format: pem, der")
	caExportCmd.Flags().StringVarP(&caExportVersion, "version", "v", "", "Export specific CA version (use v1, v2, etc. for ordinal or full version ID)")
	caExportCmd.Flags().BoolVar(&caExportAll, "all", false, "Export all CA versions (for versioned CAs)")

	// List flags
	caListCmd.Flags().StringVarP(&caListDir, "dir", "d", ".", "Directory containing CAs")

	// Init flags
	initFlags := caInitCmd.Flags()
	initFlags.StringVarP(&caInitDir, "ca-dir", "d", "./ca", "CA directory")
	initFlags.StringArrayVarP(&caInitProfiles, "profile", "P", nil, "CA profile (repeatable for multi-profile CA, e.g., ec/root-ca, ml-dsa/root-ca)")
	initFlags.StringArrayVar(&caInitVars, "var", nil, "Variable value (key=value, repeatable)")
	initFlags.StringVar(&caInitVarFile, "var-file", "", "YAML file with variable values")
	initFlags.IntVar(&caInitValidityYears, "validity", 10, "Validity period in years (overrides profile)")
	initFlags.IntVar(&caInitPathLen, "path-len", 1, "Maximum path length constraint (overrides profile)")
	initFlags.StringVarP(&caInitPassphrase, "passphrase", "p", "", "Passphrase for private key (or env:VAR_NAME)")
	initFlags.StringVar(&caInitParentDir, "parent", "", "Parent CA directory (creates subordinate CA)")
	initFlags.StringVar(&caInitParentPassphrase, "parent-passphrase", "", "Parent CA private key passphrase")

	// HSM flags (for using existing key in HSM)
	initFlags.StringVar(&caInitHSMConfig, "hsm-config", "", "Path to HSM configuration file (enables HSM mode)")
	initFlags.StringVar(&caInitKeyLabel, "key-label", "", "Key label in HSM (required with --hsm-config)")
	initFlags.StringVar(&caInitKeyID, "key-id", "", "Key ID in HSM (hex, optional with --hsm-config)")
	initFlags.BoolVar(&caInitGenerateKey, "generate-key", false, "Generate new key in HSM (requires --hsm-config and --key-label)")

	_ = caInitCmd.MarkFlagRequired("profile")

	// Info flags
	caInfoCmd.Flags().StringVarP(&caInfoDir, "ca-dir", "d", "./ca", "CA directory")
}

func runCAInit(cmd *cobra.Command, args []string) error {
	// Delegate to subordinate CA initialization if parent is specified
	if caInitParentDir != "" {
		return runCAInitSubordinate(cmd, args)
	}

	// Delegate to HSM initialization if HSM config is specified
	if caInitHSMConfig != "" {
		return runCAInitHSM(cmd, args)
	}

	// Multi-profile initialization if multiple profiles provided
	if len(caInitProfiles) > 1 {
		return runCAInitMultiProfile(cmd, args)
	}

	// Validate flags
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}
	if len(caInitProfiles) == 0 {
		return fmt.Errorf("at least one --profile is required")
	}

	// Load profile
	caInitProfile := caInitProfiles[0]
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Load and validate variables
	varValues, err := loadAndValidateProfileVariables(prof, caInitVarFile, caInitVars)
	if err != nil {
		return err
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
	}

	// Extract algorithm information from profile
	algInfo, err := extractProfileAlgorithmInfo(prof)
	if err != nil {
		return err
	}

	// Allow CLI flags to override profile values
	if cmd.Flags().Changed("validity") {
		algInfo.ValidityYears = caInitValidityYears
	}
	if cmd.Flags().Changed("path-len") {
		algInfo.PathLen = caInitPathLen
	}

	fmt.Printf("Using profile: %s\n", caInitProfile)

	if !algInfo.Algorithm.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for signing", algInfo.Algorithm)
	}

	// Expand path and check store
	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}
	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	// Build CA configuration
	cfg, err := buildCAConfigFromProfile(prof, subject, algInfo, caInitPassphrase)
	if err != nil {
		return err
	}

	// Initialize CA
	fmt.Printf("Initializing CA at %s...\n", absDir)
	fmt.Printf("  Algorithm: %s\n", algInfo.Algorithm.Description())
	if cfg.HybridConfig != nil {
		fmt.Printf("  Hybrid PQC: %s\n", cfg.HybridConfig.Algorithm.Description())
	}

	newCA, err := initializeCAByType(store, cfg, algInfo.IsComposite)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	printCAInitSuccess(newCA, absDir, cfg, algInfo.IsComposite)

	return nil
}

// runCAInitMultiProfile creates a CA with multiple algorithm profiles.
// Each profile results in a separate CA certificate, stored in version directories by algorithm family.
func runCAInitMultiProfile(cmd *cobra.Command, args []string) error {
	// Check mutual exclusivity of --var and --var-file
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}

	// Load and validate variables
	varValues, err := profile.LoadVariables(caInitVarFile, caInitVars)
	if err != nil {
		return fmt.Errorf("failed to load variables: %w", err)
	}

	// Load all profiles
	profiles := make([]*profile.Profile, 0, len(caInitProfiles))
	for _, profileName := range caInitProfiles {
		prof, err := profile.LoadProfile(profileName)
		if err != nil {
			return fmt.Errorf("failed to load profile %s: %w", profileName, err)
		}

		// Validate variables against first profile with variables
		if len(prof.Variables) > 0 && len(varValues) > 0 {
			engine, err := profile.NewTemplateEngine(prof)
			if err != nil {
				return fmt.Errorf("failed to create template engine for %s: %w", profileName, err)
			}
			rendered, err := engine.Render(varValues)
			if err != nil {
				return fmt.Errorf("failed to validate variables for %s: %w", profileName, err)
			}
			varValues = rendered.ResolvedValues
		}

		profiles = append(profiles, prof)
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
	}

	// Expand path
	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	// Check if directory already exists
	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	fmt.Printf("Initializing multi-profile CA at %s...\n", absDir)
	for _, prof := range profiles {
		fmt.Printf("  Profile: %s (%s)\n", prof.Name, prof.GetAlgorithm().Description())
	}

	// Build multi-profile configuration
	profileConfigs := make([]ca.ProfileInitConfig, 0, len(profiles))
	for _, prof := range profiles {
		validityYears := int(prof.Validity.Hours() / 24 / 365)
		if validityYears < 1 {
			validityYears = 1
		}
		if cmd.Flags().Changed("validity") {
			validityYears = caInitValidityYears
		}

		pathLen := 1
		if prof.Extensions != nil && prof.Extensions.BasicConstraints != nil && prof.Extensions.BasicConstraints.PathLen != nil {
			pathLen = *prof.Extensions.BasicConstraints.PathLen
		}
		if cmd.Flags().Changed("path-len") {
			pathLen = caInitPathLen
		}

		profileConfigs = append(profileConfigs, ca.ProfileInitConfig{
			Profile:       prof,
			ValidityYears: validityYears,
			PathLen:       pathLen,
		})
	}

	cfg := ca.MultiProfileConfig{
		Profiles: profileConfigs,
		Variables: map[string]string{
			"cn":           subject.CommonName,
			"organization": firstOrEmpty(subject.Organization),
			"country":      firstOrEmpty(subject.Country),
		},
		Passphrase: caInitPassphrase,
	}

	// Initialize multi-profile CA
	result, err := ca.InitializeMultiProfile(absDir, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize multi-profile CA: %w", err)
	}

	fmt.Printf("\nMulti-profile CA initialized successfully!\n")
	fmt.Printf("  Version:     %s\n", result.Info.Active)
	fmt.Printf("  Profiles:    %d\n", len(result.Certificates))

	for algoFamily, cert := range result.Certificates {
		fmt.Printf("\n  [%s]\n", algoFamily)
		fmt.Printf("    Subject:     %s\n", cert.Subject.String())
		fmt.Printf("    Serial:      %X\n", cert.SerialNumber.Bytes())
		fmt.Printf("    Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("    Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("\nTo activate this version:\n")
	fmt.Printf("  pki ca activate --ca-dir %s --version %s\n", absDir, result.Info.Active)

	if caInitPassphrase == "" {
		fmt.Fprintf(os.Stderr, "\nWARNING: Private keys are not encrypted. Use --passphrase for production.\n")
	}

	return nil
}

// runCAInitHSM creates a CA using an existing key in an HSM.
func runCAInitHSM(cmd *cobra.Command, args []string) error {
	// Validate flags
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}
	if err := validateHSMFlags(caInitGenerateKey, caInitKeyLabel, caInitKeyID); err != nil {
		return err
	}
	if len(caInitProfiles) != 1 {
		return fmt.Errorf("HSM mode requires exactly one --profile (multi-profile not supported with HSM)")
	}

	// Load HSM configuration
	hsmCfg, err := crypto.LoadHSMConfig(caInitHSMConfig)
	if err != nil {
		return fmt.Errorf("failed to load HSM config: %w", err)
	}

	// Load profile
	caInitProfile := caInitProfiles[0]
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Get algorithm and validate HSM compatibility
	alg := prof.GetAlgorithm()
	if !alg.IsValid() {
		return fmt.Errorf("profile %s has invalid algorithm: %s", caInitProfile, alg)
	}
	if err := validateHSMProfile(prof, alg, caInitProfile); err != nil {
		return err
	}

	// Load and validate variables
	varValues, err := loadAndValidateProfileVariables(prof, caInitVarFile, caInitVars)
	if err != nil {
		return err
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
	}

	// Extract algorithm info and apply CLI overrides
	algInfo, err := extractProfileAlgorithmInfo(prof)
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("validity") {
		algInfo.ValidityYears = caInitValidityYears
	}
	if cmd.Flags().Changed("path-len") {
		algInfo.PathLen = caInitPathLen
	}

	fmt.Printf("Using profile: %s\n", caInitProfile)
	fmt.Printf("HSM config: %s\n", caInitHSMConfig)

	// Validate and prepare store
	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}
	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}

	// Generate key in HSM if requested
	keyLabel, keyID := caInitKeyLabel, caInitKeyID
	if caInitGenerateKey {
		keyLabel, keyID, err = generateHSMKey(hsmCfg, alg, caInitKeyLabel)
		if err != nil {
			return err
		}
	}

	// Create and connect to HSM signer
	pkcs11Cfg, err := hsmCfg.ToPKCS11Config(keyLabel, keyID)
	if err != nil {
		return fmt.Errorf("failed to create PKCS#11 config: %w", err)
	}

	fmt.Printf("Connecting to HSM...\n")
	signer, err := crypto.NewPKCS11Signer(*pkcs11Cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to HSM: %w", err)
	}
	defer func() { _ = signer.Close() }()

	// Verify algorithm matches
	signerAlg := signer.Algorithm()
	if !isCompatibleAlgorithm(alg, signerAlg) {
		return fmt.Errorf("HSM key algorithm %s does not match profile algorithm %s", signerAlg, alg)
	}

	fmt.Printf("Initializing CA at %s...\n", absDir)
	fmt.Printf("  Algorithm: %s (from HSM)\n", signerAlg.Description())

	// Build configuration and initialize CA
	cfg := ca.Config{
		CommonName:    subject.CommonName,
		Organization:  firstOrEmpty(subject.Organization),
		Country:       firstOrEmpty(subject.Country),
		Algorithm:     signerAlg,
		ValidityYears: algInfo.ValidityYears,
		PathLen:       algInfo.PathLen,
		Extensions:    prof.Extensions,
	}

	newCA, err := ca.InitializeWithSigner(store, cfg, signer)
	if err != nil {
		return fmt.Errorf("failed to initialize CA: %w", err)
	}

	// Copy HSM config and update metadata
	hsmRefPath := filepath.Join(absDir, "hsm.yaml")
	if err := copyHSMConfig(caInitHSMConfig, hsmRefPath); err != nil {
		return fmt.Errorf("failed to copy HSM config: %w", err)
	}

	metadata := newCA.Info()
	metadata.AddKey(ca.KeyRef{
		ID:        "default",
		Algorithm: signerAlg,
		Storage:   ca.CreatePKCS11KeyRef("hsm.yaml", keyLabel, keyID),
	})
	if err := metadata.Save(); err != nil {
		return fmt.Errorf("failed to save CA metadata: %w", err)
	}

	// Print success
	cert := newCA.Certificate()
	fmt.Printf("\nCA initialized successfully!\n")
	fmt.Printf("  Subject:     %s\n", cert.Subject.String())
	fmt.Printf("  Serial:      %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("  Not Before:  %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Not After:   %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Certificate: %s\n", store.CACertPath())
	fmt.Printf("  Key:         HSM (%s)\n", caInitHSMConfig)
	fmt.Printf("  HSM Config:  %s\n", hsmRefPath)

	return nil
}

// isCompatibleAlgorithm checks if two algorithms are compatible (same key type).
func isCompatibleAlgorithm(profile, hsm crypto.AlgorithmID) bool {
	// For now, require exact match or compatible EC curves
	// Allow EC curves to match (e.g., profile ecdsa-p384 with HSM ecdsa-p384)
	return profile == hsm
}

// copyHSMConfig copies the HSM configuration file to the CA directory.
func copyHSMConfig(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source HSM config: %w", err)
	}
	return os.WriteFile(dst, data, 0600)
}

// runCAInitSubordinate creates a subordinate CA signed by a parent CA.
func runCAInitSubordinate(cmd *cobra.Command, args []string) error {
	// Validate flags
	if caInitVarFile != "" && len(caInitVars) > 0 {
		return fmt.Errorf("--var and --var-file are mutually exclusive")
	}
	if len(caInitProfiles) != 1 {
		return fmt.Errorf("subordinate CA requires exactly one --profile (multi-profile subordinate CA not yet supported)")
	}

	// Load profile
	caInitProfile := caInitProfiles[0]
	prof, err := profile.LoadProfile(caInitProfile)
	if err != nil {
		return fmt.Errorf("failed to load profile %s: %w", caInitProfile, err)
	}

	// Load and validate variables
	varValues, err := loadAndValidateProfileVariables(prof, caInitVarFile, caInitVars)
	if err != nil {
		return err
	}

	// Build subject from variables
	subject, err := profile.BuildSubject(varValues)
	if err != nil {
		return fmt.Errorf("failed to build subject: %w", err)
	}

	// Extract algorithm info
	algInfo, err := extractProfileAlgorithmInfo(prof)
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("validity") {
		algInfo.ValidityYears = caInitValidityYears
	}

	fmt.Printf("Using profile: %s\n", caInitProfile)

	if !algInfo.Algorithm.IsSignature() {
		return fmt.Errorf("algorithm %s is not suitable for signing", algInfo.Algorithm)
	}

	// Load parent CA
	parentCA, err := loadParentCA(caInitParentDir, caInitParentPassphrase)
	if err != nil {
		return err
	}

	// Validate and prepare store
	absDir, err := filepath.Abs(caInitDir)
	if err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}
	store := ca.NewFileStore(absDir)
	if store.Exists() {
		return fmt.Errorf("CA already exists at %s", absDir)
	}
	if err := store.Init(context.Background()); err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}

	// Create CAInfo and version structure
	algoID := string(algInfo.Algorithm)
	info := ca.NewCAInfo(ca.Subject{
		CommonName:   subject.CommonName,
		Organization: subject.Organization,
		Country:      subject.Country,
	})
	info.SetBasePath(absDir)
	info.CreateInitialVersion([]string{caInitProfile}, []string{algoID})
	if err := info.EnsureVersionDir("v1"); err != nil {
		return fmt.Errorf("failed to create version directory: %w", err)
	}

	// Generate CA key pair
	keyPath := info.KeyPath("v1", string(algInfo.Algorithm))
	keyCfg := crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    keyPath,
		Passphrase: caInitPassphrase,
	}
	km := crypto.NewKeyProvider(keyCfg)
	signer, err := km.Generate(algInfo.Algorithm, keyCfg)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Issue subordinate CA certificate
	fmt.Printf("Initializing subordinate CA at %s...\n", absDir)
	fmt.Printf("  Parent CA:  %s\n", parentCA.Certificate().Subject.String())
	fmt.Printf("  Algorithm:  %s\n", algInfo.Algorithm.Description())

	validity := time.Duration(algInfo.ValidityYears) * 365 * 24 * time.Hour
	cert, err := parentCA.Issue(context.Background(), ca.IssueRequest{
		Template:   &x509.Certificate{Subject: subject},
		PublicKey:  signer.Public(),
		Extensions: prof.Extensions,
		Validity:   validity,
	})
	if err != nil {
		return fmt.Errorf("failed to issue subordinate CA certificate: %w", err)
	}

	// Save certificate and CAInfo
	certPath := info.CertPath("v1", algoID)
	if err := saveCertToPath(certPath, cert); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}

	info.AddKey(ca.KeyRef{
		ID:        "default",
		Algorithm: algInfo.Algorithm,
		Storage: crypto.StorageRef{
			Type: "software",
			Path: fmt.Sprintf("versions/v1/keys/ca.%s.key", algoID),
		},
	})
	if err := info.Save(); err != nil {
		return fmt.Errorf("failed to save CA info: %w", err)
	}

	// Create chain file
	chainPath := filepath.Join(absDir, "chain.crt")
	if err := createChainFile(chainPath, cert, parentCA.Certificate()); err != nil {
		return err
	}

	printSubordinateCASuccess(cert, certPath, chainPath, keyPath, caInitPassphrase)

	return nil
}

func runCAInfo(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caInfoDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	store := ca.NewFileStore(absDir)
	if !store.Exists() {
		return fmt.Errorf("CA not found at %s", absDir)
	}

	caInstance, err := ca.New(store)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	cert := caInstance.Certificate()

	fmt.Printf("CA Information\n")
	fmt.Printf("==============\n\n")
	fmt.Printf("Subject:       %s\n", cert.Subject.String())
	fmt.Printf("Issuer:        %s\n", cert.Issuer.String())
	fmt.Printf("Serial:        %X\n", cert.SerialNumber.Bytes())
	fmt.Printf("Not Before:    %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
	fmt.Printf("Not After:     %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
	fmt.Printf("Algorithm:     %s\n", getSignatureAlgorithmName(cert))

	// Basic constraints
	if cert.IsCA {
		pathLen := "unlimited"
		if cert.MaxPathLen >= 0 && cert.MaxPathLenZero {
			pathLen = "0"
		} else if cert.MaxPathLen >= 0 {
			pathLen = fmt.Sprintf("%d", cert.MaxPathLen)
		}
		fmt.Printf("CA:            yes (path length: %s)\n", pathLen)
	} else {
		fmt.Printf("CA:            no\n")
	}

	// Self-signed check
	if cert.Subject.String() == cert.Issuer.String() {
		fmt.Printf("Type:          Root CA (self-signed)\n")
	} else {
		fmt.Printf("Type:          Subordinate CA\n")
	}

	fmt.Printf("\nFiles:\n")
	fmt.Printf("  Certificate: %s\n", store.CACertPath())

	// Display key paths from metadata (or fallback for legacy CAs)
	keyPaths := caInstance.KeyPaths()
	if len(keyPaths) == 1 {
		// Single key, show as "Private Key"
		for _, path := range keyPaths {
			fmt.Printf("  Private Key: %s\n", path)
		}
	} else if len(keyPaths) > 1 {
		// Multiple keys, show each with its ID
		for id, path := range keyPaths {
			fmt.Printf("  Key (%s): %s\n", id, path)
		}
	} else {
		// Fallback: no metadata, use legacy path
		fmt.Printf("  Private Key: %s\n", store.CAKeyPath())
	}

	// Check for chain file
	chainPath := filepath.Join(absDir, "chain.crt")
	if _, err := os.Stat(chainPath); err == nil {
		fmt.Printf("  Chain:       %s\n", chainPath)
	}

	return nil
}

// firstOrEmpty returns the first element of a string slice, or empty string if slice is empty.
func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func runCAExport(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caExportDir)
	if err != nil {
		return fmt.Errorf("invalid CA directory: %w", err)
	}

	// Load CAInfo for versioned CAs
	info, _ := ca.LoadCAInfo(absDir)

	// Load certificates based on flags
	var certs []*x509.Certificate
	if caExportAll {
		certs, err = loadAllVersionCerts(absDir, info)
		if err != nil {
			return err
		}
	} else if caExportVersion != "" {
		certs, err = loadVersionCerts(absDir, caExportVersion, info)
		if err != nil {
			return err
		}
	}

	// If no certs loaded yet, use bundle-based loading
	if len(certs) == 0 {
		store := ca.NewFileStore(absDir)
		if !store.Exists() {
			return fmt.Errorf("CA not found at %s", absDir)
		}
		certs, err = loadBundleCerts(store, caExportBundle)
		if err != nil {
			return err
		}
	}

	// Encode and write output
	output, err := encodeCertificates(certs, caExportFormat)
	if err != nil {
		return err
	}

	return writeExportOutput(output, caExportOut, len(certs))
}

func parseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
		data = rest
	}
	return certs, nil
}

func runCAList(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(caListDir)
	if err != nil {
		return fmt.Errorf("invalid directory: %w", err)
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	type caInfo struct {
		Name      string
		Type      string
		Algorithm string
		Expires   time.Time
	}

	var cas []caInfo

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		caDir := filepath.Join(absDir, entry.Name())
		store := ca.NewFileStore(caDir)
		if !store.Exists() {
			continue
		}

		cert, err := store.LoadCACert(context.Background())
		if err != nil {
			continue
		}

		caType := "Root CA"
		if cert.Subject.String() != cert.Issuer.String() {
			caType = "Subordinate"
		}

		cas = append(cas, caInfo{
			Name:      entry.Name(),
			Type:      caType,
			Algorithm: getSignatureAlgorithmName(cert),
			Expires:   cert.NotAfter,
		})
	}

	if len(cas) == 0 {
		fmt.Println("No CAs found in", absDir)
		return nil
	}

	// Print table
	fmt.Printf("%-20s %-12s %-20s %s\n", "NAME", "TYPE", "ALGORITHM", "EXPIRES")
	fmt.Printf("%-20s %-12s %-20s %s\n", "----", "----", "---------", "-------")
	for _, c := range cas {
		fmt.Printf("%-20s %-12s %-20s %s\n",
			c.Name,
			c.Type,
			c.Algorithm,
			c.Expires.Format("2006-01-02"),
		)
	}

	return nil
}

// getSignatureAlgorithmName returns a human-readable name for the certificate's signature algorithm.
// For PQC algorithms (ML-DSA, SLH-DSA) that Go's x509 doesn't recognize, it extracts the OID
// from the raw certificate and looks up the name.
func getSignatureAlgorithmName(cert *x509.Certificate) string {
	// If Go's x509 recognizes the algorithm, use its name
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return cert.SignatureAlgorithm.String()
	}

	// For unknown algorithms (PQC), extract OID from raw certificate
	oid, err := x509util.ExtractSignatureAlgorithmOID(cert.Raw)
	if err != nil {
		return "Unknown"
	}

	return x509util.AlgorithmName(oid)
}

// saveCertToPath saves a certificate to a PEM file.
func saveCertToPath(path string, cert *x509.Certificate) error {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	return nil
}

// loadCertFromPath loads a certificate from a PEM file.
func loadCertFromPath(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate found in %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
