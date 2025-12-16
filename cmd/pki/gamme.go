package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/remiblancher/pki/internal/policy"
)

var gammeCmd = &cobra.Command{
	Use:   "gamme",
	Short: "Manage certificate policy templates (gammes)",
	Long: `Manage certificate policy templates (gammes).

A gamme defines a complete certificate enrollment policy including:
  - Signature requirements (simple, hybrid-combined, hybrid-separate)
  - Encryption requirements (none, simple, hybrid-combined, hybrid-separate)
  - Algorithm choices (classical and/or PQC)
  - Validity period

Gammes are stored as YAML files in the CA's gammes/ directory.

Examples:
  # List all available gammes
  pki gamme list

  # Show details of a specific gamme
  pki gamme info hybrid-catalyst

  # Validate a custom gamme file
  pki gamme validate my-gamme.yaml

  # Install default gammes to a CA
  pki gamme install --dir ./ca`,
}

var gammeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available gammes",
	Long: `List all available gammes.

Shows both default (built-in) gammes and custom gammes from the CA directory.`,
	RunE: runGammeList,
}

var gammeInfoCmd = &cobra.Command{
	Use:   "info <name>",
	Short: "Show details of a gamme",
	Long:  `Show detailed information about a specific gamme.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runGammeInfo,
}

var gammeValidateCmd = &cobra.Command{
	Use:   "validate <file>",
	Short: "Validate a gamme YAML file",
	Long:  `Validate a gamme YAML file for correctness.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runGammeValidate,
}

var gammeInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install default gammes to a CA",
	Long: `Install the default gammes to a CA's gammes directory.

This copies the built-in gamme templates to the CA so they can be customized.`,
	RunE: runGammeInstall,
}

var (
	gammeCADir    string
	gammeOverwrite bool
)

func init() {
	// Add subcommands
	gammeCmd.AddCommand(gammeListCmd)
	gammeCmd.AddCommand(gammeInfoCmd)
	gammeCmd.AddCommand(gammeValidateCmd)
	gammeCmd.AddCommand(gammeInstallCmd)

	// Flags for list command
	gammeListCmd.Flags().StringVarP(&gammeCADir, "dir", "d", "./ca", "CA directory")

	// Flags for info command
	gammeInfoCmd.Flags().StringVarP(&gammeCADir, "dir", "d", "./ca", "CA directory")

	// Flags for install command
	gammeInstallCmd.Flags().StringVarP(&gammeCADir, "dir", "d", "./ca", "CA directory")
	gammeInstallCmd.Flags().BoolVar(&gammeOverwrite, "overwrite", false, "Overwrite existing gammes")
}

func runGammeList(cmd *cobra.Command, args []string) error {
	// Get default gammes
	defaultGammes, err := policy.DefaultGammes()
	if err != nil {
		return fmt.Errorf("failed to load default gammes: %w", err)
	}

	// Try to load custom gammes from CA
	var customGammes map[string]*policy.Gamme
	absDir, _ := filepath.Abs(gammeCADir)
	gammeStore := policy.NewGammeStore(absDir)
	if err := gammeStore.Load(); err == nil {
		customGammes = gammeStore.All()
	}

	// Print gammes
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tMODE\tSIGNATURE\tENCRYPTION\tCERTS\tSOURCE")
	fmt.Fprintln(w, "----\t----\t---------\t----------\t-----\t------")

	// Print default gammes
	for name, g := range defaultGammes {
		source := "default"
		if _, exists := customGammes[name]; exists {
			source = "custom (overrides default)"
		}
		printGammeRow(w, g, source)
	}

	// Print custom-only gammes
	for name, g := range customGammes {
		if _, isDefault := defaultGammes[name]; !isDefault {
			printGammeRow(w, g, "custom")
		}
	}

	w.Flush()
	return nil
}

func printGammeRow(w *tabwriter.Writer, g *policy.Gamme, source string) {
	sigAlg := string(g.Signature.Algorithms.Primary)
	if g.Signature.Algorithms.Alternative != "" {
		sigAlg += " + " + string(g.Signature.Algorithms.Alternative)
	}

	encAlg := "none"
	if g.Encryption.Required && g.Encryption.Mode != policy.EncryptionNone {
		encAlg = string(g.Encryption.Algorithms.Primary)
		if g.Encryption.Algorithms.Alternative != "" {
			encAlg += " + " + string(g.Encryption.Algorithms.Alternative)
		}
	}

	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
		g.Name,
		g.Signature.Mode,
		sigAlg,
		encAlg,
		g.CertificateCount(),
		source)
}

func runGammeInfo(cmd *cobra.Command, args []string) error {
	name := args[0]

	// Try to find gamme
	var gamme *policy.Gamme
	var source string

	// Check custom gammes first
	absDir, _ := filepath.Abs(gammeCADir)
	gammeStore := policy.NewGammeStore(absDir)
	if err := gammeStore.Load(); err == nil {
		if g, ok := gammeStore.Get(name); ok {
			gamme = g
			source = "custom (" + gammeStore.BasePath() + ")"
		}
	}

	// Fall back to default
	if gamme == nil {
		g, err := policy.GetDefaultGamme(name)
		if err != nil {
			return fmt.Errorf("gamme not found: %s", name)
		}
		gamme = g
		source = "default (built-in)"
	}

	// Print details
	fmt.Printf("Name:        %s\n", gamme.Name)
	fmt.Printf("Description: %s\n", gamme.Description)
	fmt.Printf("Source:      %s\n", source)
	fmt.Printf("Validity:    %s\n", gamme.Validity)
	fmt.Printf("Certificates: %d\n", gamme.CertificateCount())
	fmt.Println()

	fmt.Println("Signature:")
	fmt.Printf("  Mode:        %s\n", gamme.Signature.Mode)
	fmt.Printf("  Primary:     %s\n", gamme.Signature.Algorithms.Primary)
	if gamme.Signature.Algorithms.Alternative != "" {
		fmt.Printf("  Alternative: %s\n", gamme.Signature.Algorithms.Alternative)
	}
	fmt.Println()

	fmt.Println("Encryption:")
	if !gamme.Encryption.Required || gamme.Encryption.Mode == policy.EncryptionNone {
		fmt.Println("  Not required")
	} else {
		fmt.Printf("  Mode:        %s\n", gamme.Encryption.Mode)
		fmt.Printf("  Primary:     %s\n", gamme.Encryption.Algorithms.Primary)
		if gamme.Encryption.Algorithms.Alternative != "" {
			fmt.Printf("  Alternative: %s\n", gamme.Encryption.Algorithms.Alternative)
		}
	}

	return nil
}

func runGammeValidate(cmd *cobra.Command, args []string) error {
	path := args[0]

	gamme, err := policy.LoadGammeFromFile(path)
	if err != nil {
		fmt.Printf("INVALID: %s\n", err)
		return err
	}

	fmt.Printf("VALID: %s\n", gamme.Name)
	fmt.Printf("  %s\n", gamme.String())
	return nil
}

func runGammeInstall(cmd *cobra.Command, args []string) error {
	absDir, err := filepath.Abs(gammeCADir)
	if err != nil {
		return fmt.Errorf("invalid directory: %w", err)
	}

	fmt.Printf("Installing default gammes to %s/gammes/...\n", absDir)

	if err := policy.InstallDefaultGammes(absDir, gammeOverwrite); err != nil {
		return fmt.Errorf("failed to install gammes: %w", err)
	}

	// List installed gammes
	names, err := policy.ListDefaultGammeNames()
	if err != nil {
		return err
	}

	fmt.Println("Installed gammes:")
	for _, name := range names {
		fmt.Printf("  - %s\n", name)
	}

	return nil
}
