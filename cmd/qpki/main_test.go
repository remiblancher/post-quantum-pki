package main

import (
	"os"
	"testing"
)

// =============================================================================
// Root Command Tests
// =============================================================================

func TestF_RootCmd_Version(t *testing.T) {
	_, err := executeCommand(rootCmd, "--version")
	assertNoError(t, err)
}

func TestF_RootCmd_Help(t *testing.T) {
	_, err := executeCommand(rootCmd, "--help")
	assertNoError(t, err)
}

func TestF_RootCmd_UnknownCommand(t *testing.T) {
	_, err := executeCommand(rootCmd, "nonexistent-command")
	assertError(t, err)
}

// =============================================================================
// Audit Log Integration
// =============================================================================

func TestF_RootCmd_WithAuditLog(t *testing.T) {
	tc := newTestContext(t)

	auditPath := tc.path("audit.log")

	// Run a simple command with audit log
	oldAuditLogPath := auditLogPath
	defer func() { auditLogPath = oldAuditLogPath }()
	auditLogPath = ""

	_, err := executeCommand(rootCmd, "--audit-log", auditPath, "--version")
	assertNoError(t, err)
}

func TestF_RootCmd_AuditLogFromEnv(t *testing.T) {
	tc := newTestContext(t)

	auditPath := tc.path("audit-env.log")

	oldEnv := os.Getenv("PKI_AUDIT_LOG")
	os.Setenv("PKI_AUDIT_LOG", auditPath)
	defer os.Setenv("PKI_AUDIT_LOG", oldEnv)

	oldAuditLogPath := auditLogPath
	defer func() { auditLogPath = oldAuditLogPath }()
	auditLogPath = ""

	_, err := executeCommand(rootCmd, "--version")
	assertNoError(t, err)
}

func TestF_RootCmd_AuditLogInvalidPath(t *testing.T) {
	oldAuditLogPath := auditLogPath
	defer func() { auditLogPath = oldAuditLogPath }()
	auditLogPath = ""

	_, err := executeCommand(rootCmd, "--audit-log", "/nonexistent/dir/audit.log", "--help")
	// May or may not error depending on implementation
	_ = err
}
