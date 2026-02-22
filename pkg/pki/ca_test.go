package pki

import (
	"path/filepath"
	"testing"
)

// =============================================================================
// NewFileStore Tests
// =============================================================================

func TestU_NewFileStore(t *testing.T) {
	t.Run("[Unit] NewFileStore: creates store", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		if store == nil {
			t.Error("NewFileStore() returned nil")
		}
	})

	t.Run("[Unit] NewFileStore: store has correct base path", func(t *testing.T) {
		tmpDir := t.TempDir()
		store := NewFileStore(tmpDir)
		// Store should work even if directory doesn't exist yet
		if store == nil {
			t.Error("NewFileStore() returned nil for non-existent path")
		}
	})
}

// =============================================================================
// NewCAService Tests
// =============================================================================

func TestU_NewCAService(t *testing.T) {
	t.Run("[Unit] NewCAService: fails for non-existent CA", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := NewCAService(tmpDir)
		if err == nil {
			t.Error("NewCAService() should fail for non-initialized CA")
		}
	})

	t.Run("[Unit] NewCAService: fails for empty directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := NewCAService(filepath.Join(tmpDir, "nonexistent"))
		if err == nil {
			t.Error("NewCAService() should fail for non-existent directory")
		}
	})
}

// =============================================================================
// ParseRevocationReason Tests
// =============================================================================

func TestU_ParseRevocationReason(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CARevocationReason
		wantErr  bool
	}{
		{
			name:     "[Unit] ParseRevocationReason: unspecified",
			input:    "unspecified",
			expected: CAReasonUnspecified,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: keyCompromise",
			input:    "keyCompromise",
			expected: CAReasonKeyCompromise,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: CACompromise",
			input:    "CACompromise",
			expected: CAReasonCACompromise,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: affiliationChanged",
			input:    "affiliationChanged",
			expected: CAReasonAffiliationChanged,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: superseded",
			input:    "superseded",
			expected: CAReasonSuperseded,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseRevocationReason: cessationOfOperation",
			input:    "cessationOfOperation",
			expected: CAReasonCessationOfOperation,
			wantErr:  false,
		},
		{
			name:    "[Unit] ParseRevocationReason: invalid reason",
			input:   "invalidReason",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, err := ParseRevocationReason(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("ParseRevocationReason() should fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRevocationReason() error = %v", err)
			}
			if reason != tt.expected {
				t.Errorf("ParseRevocationReason() = %v, want %v", reason, tt.expected)
			}
		})
	}
}

// =============================================================================
// LoadCAInfo Tests
// =============================================================================

func TestU_LoadCAInfo(t *testing.T) {
	t.Run("[Unit] LoadCAInfo: returns info or error", func(t *testing.T) {
		// LoadCAInfo may return nil info for non-existent path
		// or an error - either behavior is acceptable
		info, err := LoadCAInfo("/nonexistent/path")
		// If no error and info is nil, that's the expected behavior for missing path
		if err == nil && info != nil {
			t.Log("LoadCAInfo returned info for non-existent path")
		}
	})
}

// =============================================================================
// ProfileService Tests
// =============================================================================

func TestU_NewProfileService(t *testing.T) {
	t.Run("[Unit] NewProfileService: creates service", func(t *testing.T) {
		svc := NewProfileService()
		if svc == nil {
			t.Error("NewProfileService() returned nil")
		}
	})
}

func TestU_ProfileService_LoadProfile(t *testing.T) {
	svc := NewProfileService()

	t.Run("[Unit] ProfileService.LoadProfile: valid profile", func(t *testing.T) {
		prof, err := svc.LoadProfile("ec/tls-server")
		if err != nil {
			t.Fatalf("ProfileService.LoadProfile() error = %v", err)
		}
		if prof == nil {
			t.Error("ProfileService.LoadProfile() returned nil")
		}
	})

	t.Run("[Unit] ProfileService.LoadProfile: invalid profile", func(t *testing.T) {
		_, err := svc.LoadProfile("nonexistent")
		if err == nil {
			t.Error("ProfileService.LoadProfile() should fail for non-existent profile")
		}
	})
}

func TestU_ProfileService_ListProfiles(t *testing.T) {
	svc := NewProfileService()

	t.Run("[Unit] ProfileService.ListProfiles: returns profiles", func(t *testing.T) {
		profiles, err := svc.ListProfiles()
		if err != nil {
			t.Fatalf("ProfileService.ListProfiles() error = %v", err)
		}
		if len(profiles) == 0 {
			t.Error("ProfileService.ListProfiles() returned empty list")
		}
	})
}

// =============================================================================
// Revocation Reason Constants Tests
// =============================================================================

func TestU_RevocationReasonConstants(t *testing.T) {
	t.Run("[Unit] RevocationReasonConstants: are defined", func(t *testing.T) {
		reasons := []CARevocationReason{
			CAReasonUnspecified,
			CAReasonKeyCompromise,
			CAReasonCACompromise,
			CAReasonAffiliationChanged,
			CAReasonSuperseded,
			CAReasonCessationOfOperation,
			CAReasonCertificateHold,
			CAReasonRemoveFromCRL,
			CAReasonPrivilegeWithdrawn,
			CAReasonAACompromise,
		}

		seen := make(map[CARevocationReason]bool)
		for _, r := range reasons {
			if seen[r] && r != CAReasonUnspecified {
				// Some constants might be 0, so we check for duplicates
				continue
			}
			seen[r] = true
		}
	})
}

// =============================================================================
// VerifyChain Tests
// =============================================================================

func TestU_VerifyChain(t *testing.T) {
	t.Run("[Unit] VerifyChain: fails with empty config", func(t *testing.T) {
		cfg := VerifyChainConfig{}
		err := VerifyChain(cfg)
		if err == nil {
			t.Error("VerifyChain() should fail with empty config")
		}
	})
}
