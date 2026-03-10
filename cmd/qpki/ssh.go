package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/remiblancher/qpki/internal/crypto"
	"github.com/remiblancher/qpki/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// sshCmd is the parent command for SSH certificate operations.
var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH certificate management",
	Long: `Manage SSH Certificate Authorities and certificates.

Commands:
  ca-init     Initialize a new SSH CA
  ca-info     Display SSH CA information
  issue       Issue an SSH certificate
  inspect     Inspect an SSH certificate
  list        List issued SSH certificates

Examples:
  # Initialize a user CA
  qpki ssh ca-init --name user-ca --algorithm ed25519 --type user --ca-dir ./ssh-user-ca

  # Issue a user certificate
  qpki ssh issue --ca-dir ./ssh-user-ca \
      --public-key ~/.ssh/id_ed25519.pub \
      --key-id alice@example.com \
      --principals alice,deploy \
      --validity 8h

  # Issue a host certificate
  qpki ssh issue --ca-dir ./ssh-host-ca \
      --public-key /etc/ssh/ssh_host_ed25519_key.pub \
      --key-id web01.example.com \
      --principals web01.example.com,192.168.1.10 \
      --validity 2160h

  # Inspect a certificate
  qpki ssh inspect ~/.ssh/id_ed25519-cert.pub

  # List issued certificates
  qpki ssh list --ca-dir ./ssh-user-ca`,
}

// --- ssh ca-init ---

var sshCAInitCmd = &cobra.Command{
	Use:   "ca-init",
	Short: "Initialize a new SSH Certificate Authority",
	Long: `Initialize a new SSH Certificate Authority.

Creates an SSH CA key pair for signing user or host certificates.
Best practice: use separate CAs for user and host certificates.

The CA will be created in the specified directory with the following structure:
  {dir}/
    ├── ssh-ca.meta.json    # CA metadata
    ├── ssh-ca.pub          # CA public key (authorized_keys format)
    ├── ssh-ca.key          # CA private key (PEM)
    ├── certs/              # Issued certificates
    ├── krl/                # Key Revocation Lists
    ├── serial              # Serial number counter
    └── index.json          # Certificate index

Supported algorithms: ed25519 (recommended), ecdsa-p256, ecdsa-p384, ecdsa-p521, rsa-4096
Note: PQC algorithms are NOT supported for SSH (no standard exists yet).

Examples:
  qpki ssh ca-init --name user-ca --algorithm ed25519 --type user --ca-dir ./ssh-user-ca
  qpki ssh ca-init --name host-ca --algorithm ed25519 --type host --ca-dir ./ssh-host-ca`,
	RunE: runSSHCAInit,
}

var (
	sshCAInitName      string
	sshCAInitAlgorithm string
	sshCAInitType      string
	sshCAInitDir       string
)

func runSSHCAInit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	alg, err := crypto.ParseAlgorithm(sshCAInitAlgorithm)
	if err != nil {
		return fmt.Errorf("invalid algorithm: %w", err)
	}

	store := sshca.NewFileStore(sshCAInitDir)
	ca, err := sshca.Init(ctx, store, sshCAInitName, alg, sshCAInitType)
	if err != nil {
		return err
	}

	info := ca.Info()
	fmt.Printf("SSH CA initialized successfully.\n\n")
	fmt.Printf("  Name:        %s\n", info.Name)
	fmt.Printf("  Type:        %s\n", info.CertType)
	fmt.Printf("  Algorithm:   %s\n", info.Algorithm)
	fmt.Printf("  Fingerprint: %s\n", info.PublicKey)
	fmt.Printf("  Directory:   %s\n", sshCAInitDir)
	fmt.Printf("\nPublic key saved to: %s/ssh-ca.pub\n", sshCAInitDir)

	if info.CertType == "user" {
		fmt.Printf("\nTo configure sshd to trust this CA:\n")
		fmt.Printf("  echo \"TrustedUserCAKeys %s/ssh-ca.pub\" >> /etc/ssh/sshd_config\n", sshCAInitDir)
	} else {
		fmt.Printf("\nTo configure sshd to use host certificates:\n")
		fmt.Printf("  HostCertificate /etc/ssh/ssh_host_*_key-cert.pub\n")
		fmt.Printf("\nTo configure clients to trust this CA:\n")
		fmt.Printf("  @cert-authority *.example.com $(cat %s/ssh-ca.pub)\n", sshCAInitDir)
	}

	return nil
}

// --- ssh ca-info ---

var sshCAInfoCmd = &cobra.Command{
	Use:   "ca-info",
	Short: "Display SSH CA information",
	RunE:  runSSHCAInfo,
}

var sshCAInfoDir string

func runSSHCAInfo(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	store := sshca.NewFileStore(sshCAInfoDir)

	info, err := sshca.LoadInfo(ctx, store)
	if err != nil {
		return err
	}

	fmt.Printf("SSH Certificate Authority\n\n")
	fmt.Printf("  Name:        %s\n", info.Name)
	fmt.Printf("  Type:        %s\n", info.CertType)
	fmt.Printf("  Algorithm:   %s\n", info.Algorithm)
	fmt.Printf("  Fingerprint: %s\n", info.PublicKey)
	fmt.Printf("  Created:     %s\n", info.Created.Format(time.RFC3339))
	fmt.Printf("  Directory:   %s\n", sshCAInfoDir)

	// Show index stats
	entries, err := store.ReadIndex(ctx)
	if err == nil {
		valid := 0
		revoked := 0
		for _, e := range entries {
			if e.Status == "V" {
				valid++
			} else if e.Status == "R" {
				revoked++
			}
		}
		fmt.Printf("\n  Certificates: %d total (%d valid, %d revoked)\n", len(entries), valid, revoked)
	}

	return nil
}

// --- ssh issue ---

var sshIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue an SSH certificate",
	Long: `Issue an SSH certificate signed by the specified CA.

The certificate is created for the provided public key with the specified
principals, key ID, and validity period.

For user certificates, principals are the usernames the user can authenticate as.
For host certificates, principals are the hostnames/IPs the server responds to.

Examples:
  # User certificate (8h validity)
  qpki ssh issue --ca-dir ./ssh-user-ca \
      --public-key ~/.ssh/id_ed25519.pub \
      --key-id alice@example.com \
      --principals alice,deploy \
      --validity 8h

  # Host certificate (90 days)
  qpki ssh issue --ca-dir ./ssh-host-ca \
      --public-key /etc/ssh/ssh_host_ed25519_key.pub \
      --key-id web01.example.com \
      --principals web01.example.com,192.168.1.10 \
      --validity 2160h

  # Certificate with restrictions
  qpki ssh issue --ca-dir ./ssh-user-ca \
      --public-key ~/.ssh/id_ed25519.pub \
      --key-id ci@example.com \
      --principals deploy \
      --validity 1h \
      --force-command "/usr/bin/deploy.sh" \
      --source-address "10.0.0.0/8"`,
	RunE: runSSHIssue,
}

var (
	sshIssueCADir         string
	sshIssuePublicKey     string
	sshIssueKeyID         string
	sshIssuePrincipals    string
	sshIssueValidity      string
	sshIssuePassphrase    string
	sshIssueForceCommand  string
	sshIssueSourceAddress string
	sshIssueOutput        string
	sshIssueNoPTY         bool
	sshIssueNoPortFwd     bool
	sshIssueNoAgentFwd    bool
)

func runSSHIssue(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load CA info
	store := sshca.NewFileStore(sshIssueCADir)
	info, err := sshca.LoadInfo(ctx, store)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	// Load CA signer
	alg, err := crypto.ParseAlgorithm(info.Algorithm)
	if err != nil {
		return err
	}
	kp := crypto.NewSoftwareKeyProvider()
	signer, err := kp.Load(crypto.KeyStorageConfig{
		Type:       crypto.KeyProviderTypeSoftware,
		KeyPath:    sshIssueCADir + "/ssh-ca.key",
		Passphrase: sshIssuePassphrase,
	})
	if err != nil {
		return fmt.Errorf("failed to load CA key: %w", err)
	}
	_ = alg

	ca, err := sshca.Load(ctx, store, signer)
	if err != nil {
		return err
	}

	// Read public key
	pubKeyData, err := os.ReadFile(sshIssuePublicKey)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyData)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Parse validity
	validity, err := time.ParseDuration(sshIssueValidity)
	if err != nil {
		return fmt.Errorf("invalid validity: %w", err)
	}

	// Parse principals
	principals := strings.Split(sshIssuePrincipals, ",")
	for i := range principals {
		principals[i] = strings.TrimSpace(principals[i])
	}

	// Build extensions
	var extensions map[string]string
	if info.CertType == "user" {
		extensions = sshca.DefaultUserExtensions()
		if sshIssueNoPTY {
			delete(extensions, "permit-pty")
		}
		if sshIssueNoPortFwd {
			delete(extensions, "permit-port-forwarding")
		}
		if sshIssueNoAgentFwd {
			delete(extensions, "permit-agent-forwarding")
		}
	}

	// Build critical options
	var criticalOptions map[string]string
	if sshIssueForceCommand != "" || sshIssueSourceAddress != "" {
		criticalOptions = make(map[string]string)
		if sshIssueForceCommand != "" {
			criticalOptions["force-command"] = sshIssueForceCommand
		}
		if sshIssueSourceAddress != "" {
			criticalOptions["source-address"] = sshIssueSourceAddress
		}
	}

	// Issue certificate
	cert, err := ca.Issue(ctx, sshca.IssueRequest{
		PublicKey:       pubKey,
		KeyID:           sshIssueKeyID,
		Principals:      principals,
		ValidBefore:     time.Now().Add(validity),
		CriticalOptions: criticalOptions,
		Extensions:      extensions,
	})
	if err != nil {
		return err
	}

	// Output certificate
	certData := ssh.MarshalAuthorizedKey(cert)

	if sshIssueOutput != "" {
		if err := os.WriteFile(sshIssueOutput, certData, 0644); err != nil {
			return fmt.Errorf("failed to write certificate: %w", err)
		}
		fmt.Printf("SSH certificate issued successfully.\n\n")
		fmt.Printf("  Serial:      %d\n", cert.Serial)
		fmt.Printf("  Key ID:      %s\n", cert.KeyId)
		fmt.Printf("  Type:        %s\n", info.CertType)
		fmt.Printf("  Principals:  %s\n", strings.Join(cert.ValidPrincipals, ", "))
		fmt.Printf("  Valid:       %s to %s\n",
			time.Unix(int64(cert.ValidAfter), 0).Format(time.RFC3339),
			time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339))
		fmt.Printf("  Output:      %s\n", sshIssueOutput)
	} else {
		// Write to stdout
		fmt.Print(string(certData))
	}

	return nil
}

// --- ssh inspect ---

var sshInspectCmd = &cobra.Command{
	Use:   "inspect <certificate-file>",
	Short: "Inspect an SSH certificate",
	Args:  cobra.ExactArgs(1),
	RunE:  runSSHInspect,
}

func runSSHInspect(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse SSH data: %w", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("file does not contain an SSH certificate")
	}

	certType := "user"
	if cert.CertType == ssh.HostCert {
		certType = "host"
	}

	fmt.Printf("SSH Certificate:\n\n")
	fmt.Printf("  Type:          %s certificate\n", certType)
	fmt.Printf("  Serial:        %d\n", cert.Serial)
	fmt.Printf("  Key ID:        %s\n", cert.KeyId)
	fmt.Printf("  Principals:    %s\n", strings.Join(cert.ValidPrincipals, ", "))

	validAfter := time.Unix(int64(cert.ValidAfter), 0)
	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	fmt.Printf("  Valid After:   %s\n", validAfter.Format(time.RFC3339))
	fmt.Printf("  Valid Before:  %s\n", validBefore.Format(time.RFC3339))

	now := time.Now()
	if now.Before(validAfter) {
		fmt.Printf("  Status:        NOT YET VALID\n")
	} else if now.After(validBefore) {
		fmt.Printf("  Status:        EXPIRED\n")
	} else {
		fmt.Printf("  Status:        VALID\n")
	}

	fmt.Printf("  Key Type:      %s\n", cert.Key.Type())
	fmt.Printf("  Fingerprint:   %s\n", ssh.FingerprintSHA256(cert.Key))
	fmt.Printf("  Signing CA:    %s\n", ssh.FingerprintSHA256(cert.SignatureKey))

	if len(cert.Permissions.CriticalOptions) > 0 {
		fmt.Printf("\n  Critical Options:\n")
		for k, v := range cert.Permissions.CriticalOptions {
			if v != "" {
				fmt.Printf("    %s: %s\n", k, v)
			} else {
				fmt.Printf("    %s\n", k)
			}
		}
	}

	if len(cert.Permissions.Extensions) > 0 {
		fmt.Printf("\n  Extensions:\n")
		for k := range cert.Permissions.Extensions {
			fmt.Printf("    %s\n", k)
		}
	}

	return nil
}

// --- ssh list ---

var sshListCmd = &cobra.Command{
	Use:   "list",
	Short: "List issued SSH certificates",
	RunE:  runSSHList,
}

var sshListDir string

func runSSHList(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	store := sshca.NewFileStore(sshListDir)

	entries, err := store.ReadIndex(ctx)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No certificates issued.")
		return nil
	}

	fmt.Printf("%-8s %-6s %-6s %-30s %-40s %-20s\n", "SERIAL", "STATUS", "TYPE", "KEY ID", "PRINCIPALS", "VALID BEFORE")
	fmt.Println(strings.Repeat("-", 120))

	for _, e := range entries {
		validBefore := time.Unix(int64(e.ValidBefore), 0).Format("2006-01-02 15:04")
		principals := strings.Join(e.Principals, ",")
		if len(principals) > 40 {
			principals = principals[:37] + "..."
		}
		fmt.Printf("%-8d %-6s %-6s %-30s %-40s %-20s\n",
			e.Serial, e.Status, e.CertType, e.KeyID, principals, validBefore)
	}

	return nil
}

func init() {
	// ssh ca-init
	sshCAInitCmd.Flags().StringVar(&sshCAInitName, "name", "", "CA name (required)")
	sshCAInitCmd.Flags().StringVar(&sshCAInitAlgorithm, "algorithm", "ed25519", "Key algorithm")
	sshCAInitCmd.Flags().StringVar(&sshCAInitType, "type", "", "Certificate type: user or host (required)")
	sshCAInitCmd.Flags().StringVar(&sshCAInitDir, "ca-dir", "", "CA directory (required)")
	_ = sshCAInitCmd.MarkFlagRequired("name")
	_ = sshCAInitCmd.MarkFlagRequired("type")
	_ = sshCAInitCmd.MarkFlagRequired("ca-dir")

	// ssh ca-info
	sshCAInfoCmd.Flags().StringVar(&sshCAInfoDir, "ca-dir", "", "CA directory (required)")
	_ = sshCAInfoCmd.MarkFlagRequired("ca-dir")

	// ssh issue
	sshIssueCmd.Flags().StringVar(&sshIssueCADir, "ca-dir", "", "CA directory (required)")
	sshIssueCmd.Flags().StringVar(&sshIssuePublicKey, "public-key", "", "Path to subject's public key (required)")
	sshIssueCmd.Flags().StringVar(&sshIssueKeyID, "key-id", "", "Certificate key ID (required)")
	sshIssueCmd.Flags().StringVar(&sshIssuePrincipals, "principals", "", "Comma-separated principals (required)")
	sshIssueCmd.Flags().StringVar(&sshIssueValidity, "validity", "8h", "Certificate validity duration")
	sshIssueCmd.Flags().StringVar(&sshIssuePassphrase, "passphrase", "", "CA key passphrase")
	sshIssueCmd.Flags().StringVar(&sshIssueForceCommand, "force-command", "", "Force a specific command")
	sshIssueCmd.Flags().StringVar(&sshIssueSourceAddress, "source-address", "", "Restrict to source IPs/CIDRs")
	sshIssueCmd.Flags().StringVar(&sshIssueOutput, "out", "", "Output file (default: stdout)")
	sshIssueCmd.Flags().BoolVar(&sshIssueNoPTY, "no-pty", false, "Disable permit-pty extension")
	sshIssueCmd.Flags().BoolVar(&sshIssueNoPortFwd, "no-port-forwarding", false, "Disable permit-port-forwarding")
	sshIssueCmd.Flags().BoolVar(&sshIssueNoAgentFwd, "no-agent-forwarding", false, "Disable permit-agent-forwarding")
	_ = sshIssueCmd.MarkFlagRequired("ca-dir")
	_ = sshIssueCmd.MarkFlagRequired("public-key")
	_ = sshIssueCmd.MarkFlagRequired("key-id")
	_ = sshIssueCmd.MarkFlagRequired("principals")

	// ssh inspect (takes args, no flags needed for path)

	// ssh list
	sshListCmd.Flags().StringVar(&sshListDir, "ca-dir", "", "CA directory (required)")
	_ = sshListCmd.MarkFlagRequired("ca-dir")

	// Register subcommands
	sshCmd.AddCommand(sshCAInitCmd)
	sshCmd.AddCommand(sshCAInfoCmd)
	sshCmd.AddCommand(sshIssueCmd)
	sshCmd.AddCommand(sshInspectCmd)
	sshCmd.AddCommand(sshListCmd)
}
