package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
)

// Note: t.Parallel() is not used because Cobra commands share global flag state.
// Running tests in parallel causes race conditions with flag access.

// Note: SSH commands use fmt.Printf (writing to os.Stdout), not cmd.OutOrStdout(),
// so executeCommand cannot capture their output. Tests rely on error checks and
// file-based assertions instead.

// resetSSHFlags resets all SSH-related global flags to their default values.
// This is needed because Cobra retains flag values between test runs.
func resetSSHFlags() {
	sshCAInitName = ""
	sshCAInitAlgorithm = "ed25519"
	sshCAInitType = ""
	sshCAInitDir = ""

	sshCAInfoDir = ""

	sshIssueCADir = ""
	sshIssuePublicKey = ""
	sshIssueKeyID = ""
	sshIssuePrincipals = ""
	sshIssueValidity = "8h"
	sshIssuePassphrase = ""
	sshIssueForceCommand = ""
	sshIssueSourceAddress = ""
	sshIssueOutput = ""
	sshIssueNoPTY = false
	sshIssueNoPortFwd = false
	sshIssueNoAgentFwd = false
	sshIssueProfile = ""
	sshIssueVars = nil

	sshListDir = ""

	sshRevokeCADir = ""
	sshRevokeSerial = 0
	sshRevokePassphrase = ""

	sshKRLCADir = ""
	sshKRLOutput = ""
	sshKRLPassphrase = ""
	sshKRLComment = ""

	// Reset cobra's "Changed" state so MarkFlagRequired works correctly.
	// Without this, flags set in a prior test are still considered "provided".
	for _, cmd := range []*cobra.Command{
		sshCAInitCmd, sshCAInfoCmd, sshIssueCmd,
		sshInspectCmd, sshListCmd, sshRevokeCmd, sshKRLCmd,
	} {
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			f.Changed = false
		})
	}
}

// generateSSHPublicKey generates an ed25519 SSH public key in authorized_keys format.
func generateSSHPublicKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(pub))
}

// initSSHCA is a test helper that initializes an SSH CA and returns the ca-dir path.
func initSSHCA(t *testing.T, tc *testContext, name, caType string) string {
	t.Helper()
	resetSSHFlags()
	caDir := tc.path(name)
	_, err := executeCommand(rootCmd, "ssh", "ca-init",
		"--name", name,
		"--type", caType,
		"--algorithm", "ed25519",
		"--ca-dir", caDir,
	)
	if err != nil {
		t.Fatalf("failed to init SSH CA: %v", err)
	}
	return caDir
}

// issueSSHCert is a test helper that issues a cert and returns the output path.
func issueSSHCert(t *testing.T, tc *testContext, caDir, keyID, principals string) string {
	t.Helper()
	resetSSHFlags()
	pubKey := generateSSHPublicKey(t)
	pubKeyPath := tc.writeFile(keyID+".pub", pubKey)
	certPath := tc.path(keyID + "-cert.pub")

	_, err := executeCommand(rootCmd, "ssh", "issue",
		"--ca-dir", caDir,
		"--public-key", pubKeyPath,
		"--key-id", keyID,
		"--principals", principals,
		"--validity", "8h",
		"--out", certPath,
	)
	if err != nil {
		t.Fatalf("failed to issue SSH cert: %v", err)
	}
	return certPath
}

// serialToString converts a uint64 serial number to its string representation.
func serialToString(serial uint64) string {
	if serial == 0 {
		return "0"
	}
	s := make([]byte, 0, 20)
	n := serial
	for n > 0 {
		s = append([]byte{byte('0' + n%10)}, s...)
		n /= 10
	}
	return string(s)
}

// =============================================================================
// Unit Tests
// =============================================================================

func TestU_SplitAndTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "[Unit] SplitAndTrim: simple comma-separated",
			input:    "alice,bob,charlie",
			expected: []string{"alice", "bob", "charlie"},
		},
		{
			name:     "[Unit] SplitAndTrim: with spaces",
			input:    " alice , bob , charlie ",
			expected: []string{"alice", "bob", "charlie"},
		},
		{
			name:     "[Unit] SplitAndTrim: single value",
			input:    "alice",
			expected: []string{"alice"},
		},
		{
			name:     "[Unit] SplitAndTrim: empty string",
			input:    "",
			expected: []string{""},
		},
		{
			name:     "[Unit] SplitAndTrim: trailing comma",
			input:    "alice,bob,",
			expected: []string{"alice", "bob", ""},
		},
		{
			name:     "[Unit] SplitAndTrim: lots of whitespace",
			input:    "  alice  ,  bob  ",
			expected: []string{"alice", "bob"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitAndTrim(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d elements, got %d: %v", len(tt.expected), len(result), result)
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("element %d: expected %q, got %q", i, tt.expected[i], result[i])
				}
			}
		})
	}
}

// =============================================================================
// SSH CA Init Tests
// =============================================================================

func TestF_SSH_CAInit_Success(t *testing.T) {
	tc := newTestContext(t)
	resetSSHFlags()

	caDir := tc.path("user-ca")
	_, err := executeCommand(rootCmd, "ssh", "ca-init",
		"--name", "test-user-ca",
		"--type", "user",
		"--algorithm", "ed25519",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	// Verify CA directory structure
	assertFileExists(t, filepath.Join(caDir, "ssh-ca.pub"))
	assertFileExists(t, filepath.Join(caDir, "ssh-ca.key"))
	assertFileExists(t, filepath.Join(caDir, "ssh-ca.meta.json"))
	assertFileNotEmpty(t, filepath.Join(caDir, "ssh-ca.pub"))
	assertFileNotEmpty(t, filepath.Join(caDir, "ssh-ca.key"))
}

func TestF_SSH_CAInit_Host(t *testing.T) {
	tc := newTestContext(t)
	resetSSHFlags()

	caDir := tc.path("host-ca")
	_, err := executeCommand(rootCmd, "ssh", "ca-init",
		"--name", "test-host-ca",
		"--type", "host",
		"--algorithm", "ed25519",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)

	assertFileExists(t, filepath.Join(caDir, "ssh-ca.pub"))
	assertFileExists(t, filepath.Join(caDir, "ssh-ca.key"))
	assertFileExists(t, filepath.Join(caDir, "ssh-ca.meta.json"))
}

func TestF_SSH_CAInit_MissingFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "[Functional] CAInit: MissingName",
			args: []string{"ssh", "ca-init", "--type", "user", "--ca-dir", "/tmp/qpki-test-missing-name"},
		},
		{
			name: "[Functional] CAInit: MissingType",
			args: []string{"ssh", "ca-init", "--name", "test", "--ca-dir", "/tmp/qpki-test-missing-type"},
		},
		{
			name: "[Functional] CAInit: MissingCADir",
			args: []string{"ssh", "ca-init", "--name", "test", "--type", "user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetSSHFlags()
			_, err := executeCommand(rootCmd, tt.args...)
			assertError(t, err)
		})
	}
}

func TestF_SSH_CAInit_InvalidAlgorithm(t *testing.T) {
	tc := newTestContext(t)
	resetSSHFlags()

	caDir := tc.path("bad-algo-ca")
	_, err := executeCommand(rootCmd, "ssh", "ca-init",
		"--name", "test-ca",
		"--type", "user",
		"--algorithm", "not-a-real-algorithm",
		"--ca-dir", caDir,
	)
	assertError(t, err)
}

// =============================================================================
// SSH CA Info Tests
// =============================================================================

func TestF_SSH_CAInfo_Success(t *testing.T) {
	tc := newTestContext(t)

	// Init a CA first
	caDir := initSSHCA(t, tc, "info-ca", "user")

	// ca-info should succeed on the initialized CA
	resetSSHFlags()
	_, err := executeCommand(rootCmd, "ssh", "ca-info",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)
}

func TestF_SSH_CAInfo_NotFound(t *testing.T) {
	tc := newTestContext(t)
	resetSSHFlags()

	_, err := executeCommand(rootCmd, "ssh", "ca-info",
		"--ca-dir", tc.path("nonexistent-ca"),
	)
	assertError(t, err)
}

// =============================================================================
// SSH Issue Tests
// =============================================================================

func TestF_SSH_Issue_Success(t *testing.T) {
	tc := newTestContext(t)

	// Init CA
	caDir := initSSHCA(t, tc, "issue-ca", "user")

	// Generate SSH public key and write to file
	resetSSHFlags()
	pubKey := generateSSHPublicKey(t)
	pubKeyPath := tc.writeFile("user.pub", pubKey)
	certPath := tc.path("user-cert.pub")

	_, err := executeCommand(rootCmd, "ssh", "issue",
		"--ca-dir", caDir,
		"--public-key", pubKeyPath,
		"--key-id", "alice@example.com",
		"--principals", "alice,deploy",
		"--validity", "8h",
		"--out", certPath,
	)
	assertNoError(t, err)

	assertFileExists(t, certPath)
	assertFileNotEmpty(t, certPath)

	// Verify the output is a valid SSH certificate with correct fields
	certData, err := os.ReadFile(certPath)
	assertNoError(t, err)
	pubParsed, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	assertNoError(t, err)
	cert, ok := pubParsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("output is not an SSH certificate")
	}
	if cert.KeyId != "alice@example.com" {
		t.Errorf("expected key ID alice@example.com, got %s", cert.KeyId)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("expected user cert type, got %d", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 2 {
		t.Errorf("expected 2 principals, got %d", len(cert.ValidPrincipals))
	}
	if cert.ValidPrincipals[0] != "alice" || cert.ValidPrincipals[1] != "deploy" {
		t.Errorf("expected principals [alice deploy], got %v", cert.ValidPrincipals)
	}
	// User certificates should have default extensions
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Error("expected permit-pty extension in user cert")
	}
}

func TestF_SSH_Issue_WithRestrictions(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "restrict-ca", "user")

	resetSSHFlags()
	pubKey := generateSSHPublicKey(t)
	pubKeyPath := tc.writeFile("restricted.pub", pubKey)
	certPath := tc.path("restricted-cert.pub")

	_, err := executeCommand(rootCmd, "ssh", "issue",
		"--ca-dir", caDir,
		"--public-key", pubKeyPath,
		"--key-id", "ci@example.com",
		"--principals", "deploy",
		"--validity", "1h",
		"--force-command", "/usr/bin/deploy.sh",
		"--source-address", "10.0.0.0/8",
		"--no-pty",
		"--out", certPath,
	)
	assertNoError(t, err)
	assertFileExists(t, certPath)

	// Parse and verify restrictions
	certData, err := os.ReadFile(certPath)
	assertNoError(t, err)
	pubParsed, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	assertNoError(t, err)
	cert, ok := pubParsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("output is not an SSH certificate")
	}

	if cert.CriticalOptions["force-command"] != "/usr/bin/deploy.sh" {
		t.Errorf("expected force-command=/usr/bin/deploy.sh, got: %v", cert.CriticalOptions)
	}
	if cert.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Errorf("expected source-address=10.0.0.0/8, got: %v", cert.CriticalOptions)
	}
	if _, hasPTY := cert.Extensions["permit-pty"]; hasPTY {
		t.Error("expected permit-pty to be removed with --no-pty")
	}
}

func TestF_SSH_Issue_MissingKeyID(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "missing-keyid-ca", "user")

	resetSSHFlags()
	pubKey := generateSSHPublicKey(t)
	pubKeyPath := tc.writeFile("nokey.pub", pubKey)

	_, err := executeCommand(rootCmd, "ssh", "issue",
		"--ca-dir", caDir,
		"--public-key", pubKeyPath,
		"--principals", "alice",
		"--validity", "8h",
	)
	assertError(t, err)
}

func TestF_SSH_Issue_MissingPrincipals(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "missing-princ-ca", "user")

	resetSSHFlags()
	pubKey := generateSSHPublicKey(t)
	pubKeyPath := tc.writeFile("noprinc.pub", pubKey)

	_, err := executeCommand(rootCmd, "ssh", "issue",
		"--ca-dir", caDir,
		"--public-key", pubKeyPath,
		"--key-id", "alice@example.com",
		"--validity", "8h",
	)
	assertError(t, err)
}

func TestF_SSH_Issue_PublicKeyNotFound(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "nokey-ca", "user")

	resetSSHFlags()
	_, err := executeCommand(rootCmd, "ssh", "issue",
		"--ca-dir", caDir,
		"--public-key", tc.path("does-not-exist.pub"),
		"--key-id", "test@example.com",
		"--principals", "test",
		"--validity", "8h",
	)
	assertError(t, err)
}

// =============================================================================
// SSH List Tests
// =============================================================================

func TestF_SSH_List_Empty(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "list-empty-ca", "user")

	resetSSHFlags()
	_, err := executeCommand(rootCmd, "ssh", "list",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)
}

func TestF_SSH_List_WithCerts(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "list-certs-ca", "user")

	// Issue a certificate
	certPath := issueSSHCert(t, tc, caDir, "listuser@example.com", "listuser")
	assertFileExists(t, certPath)

	resetSSHFlags()
	_, err := executeCommand(rootCmd, "ssh", "list",
		"--ca-dir", caDir,
	)
	assertNoError(t, err)
}

// =============================================================================
// SSH Inspect Tests
// =============================================================================

func TestF_SSH_Inspect_Success(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "inspect-ca", "user")
	certPath := issueSSHCert(t, tc, caDir, "inspect@example.com", "inspectuser")

	resetSSHFlags()
	_, err := executeCommand(rootCmd, "ssh", "inspect", certPath)
	assertNoError(t, err)
}

func TestF_SSH_Inspect_NotACert(t *testing.T) {
	tc := newTestContext(t)

	// Write a regular public key (not a certificate)
	pubKey := generateSSHPublicKey(t)
	pubKeyPath := tc.writeFile("plain.pub", pubKey)

	resetSSHFlags()
	_, err := executeCommand(rootCmd, "ssh", "inspect", pubKeyPath)
	assertError(t, err)
}

func TestF_SSH_Inspect_FileNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetSSHFlags()

	_, err := executeCommand(rootCmd, "ssh", "inspect", tc.path("nonexistent-cert.pub"))
	assertError(t, err)
}

// =============================================================================
// SSH Revoke Tests
// =============================================================================

func TestF_SSH_Revoke_Success(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "revoke-ca", "user")
	certPath := issueSSHCert(t, tc, caDir, "revoke@example.com", "revokeuser")

	// Parse the cert to get its serial
	certData, err := os.ReadFile(certPath)
	assertNoError(t, err)
	pubParsed, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	assertNoError(t, err)
	cert := pubParsed.(*ssh.Certificate)

	resetSSHFlags()
	serialStr := serialToString(cert.Serial)
	_, err = executeCommand(rootCmd, "ssh", "revoke",
		"--ca-dir", caDir,
		"--serial", serialStr,
	)
	assertNoError(t, err)

	// Verify KRL file was generated
	assertFileExists(t, filepath.Join(caDir, "krl", "krl.bin"))
	assertFileNotEmpty(t, filepath.Join(caDir, "krl", "krl.bin"))
}

func TestF_SSH_Revoke_CAdirNotFound(t *testing.T) {
	tc := newTestContext(t)
	resetSSHFlags()

	_, err := executeCommand(rootCmd, "ssh", "revoke",
		"--ca-dir", tc.path("nonexistent-ca"),
		"--serial", "999",
	)
	assertError(t, err)
}

// =============================================================================
// SSH KRL Tests
// =============================================================================

func TestF_SSH_KRL_Success(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "krl-ca", "user")
	certPath := issueSSHCert(t, tc, caDir, "krl@example.com", "krluser")

	// Get serial from issued cert
	certData, err := os.ReadFile(certPath)
	assertNoError(t, err)
	pubParsed, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	assertNoError(t, err)
	cert := pubParsed.(*ssh.Certificate)

	// Revoke the cert first
	resetSSHFlags()
	serialStr := serialToString(cert.Serial)
	_, err = executeCommand(rootCmd, "ssh", "revoke",
		"--ca-dir", caDir,
		"--serial", serialStr,
	)
	assertNoError(t, err)

	// Generate KRL to a custom output path
	resetSSHFlags()
	krlPath := tc.path("krl.bin")
	_, err = executeCommand(rootCmd, "ssh", "krl",
		"--ca-dir", caDir,
		"--out", krlPath,
		"--comment", "test KRL",
	)
	assertNoError(t, err)

	assertFileExists(t, krlPath)
	assertFileNotEmpty(t, krlPath)
}

func TestF_SSH_KRL_Empty(t *testing.T) {
	tc := newTestContext(t)

	caDir := initSSHCA(t, tc, "krl-empty-ca", "user")

	resetSSHFlags()
	krlPath := tc.path("empty-krl.bin")
	_, err := executeCommand(rootCmd, "ssh", "krl",
		"--ca-dir", caDir,
		"--out", krlPath,
	)
	assertNoError(t, err)

	assertFileExists(t, krlPath)
}
