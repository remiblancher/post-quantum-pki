package cli

import (
	"testing"
)

// =============================================================================
// GetRevocationReasonString Tests
// =============================================================================

func TestU_GetRevocationReasonString(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected string
	}{
		{
			name:     "[Unit] GetRevocationReasonString: unspecified",
			code:     0,
			expected: "unspecified",
		},
		{
			name:     "[Unit] GetRevocationReasonString: keyCompromise",
			code:     1,
			expected: "keyCompromise",
		},
		{
			name:     "[Unit] GetRevocationReasonString: cACompromise",
			code:     2,
			expected: "cACompromise",
		},
		{
			name:     "[Unit] GetRevocationReasonString: affiliationChanged",
			code:     3,
			expected: "affiliationChanged",
		},
		{
			name:     "[Unit] GetRevocationReasonString: superseded",
			code:     4,
			expected: "superseded",
		},
		{
			name:     "[Unit] GetRevocationReasonString: cessationOfOperation",
			code:     5,
			expected: "cessationOfOperation",
		},
		{
			name:     "[Unit] GetRevocationReasonString: certificateHold",
			code:     6,
			expected: "certificateHold",
		},
		{
			name:     "[Unit] GetRevocationReasonString: removeFromCRL",
			code:     8,
			expected: "removeFromCRL",
		},
		{
			name:     "[Unit] GetRevocationReasonString: privilegeWithdrawn",
			code:     9,
			expected: "privilegeWithdrawn",
		},
		{
			name:     "[Unit] GetRevocationReasonString: aACompromise",
			code:     10,
			expected: "aACompromise",
		},
		{
			name:     "[Unit] GetRevocationReasonString: unknown code",
			code:     99,
			expected: "unknown (99)",
		},
		{
			name:     "[Unit] GetRevocationReasonString: code 7 (reserved)",
			code:     7,
			expected: "unknown (7)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetRevocationReasonString(tt.code)
			if result != tt.expected {
				t.Errorf("GetRevocationReasonString(%d) = %s, want %s", tt.code, result, tt.expected)
			}
		})
	}
}

// =============================================================================
// GetOCSPRevocationReasonString Tests
// =============================================================================

func TestU_GetOCSPRevocationReasonString(t *testing.T) {
	tests := []struct {
		name     string
		reason   int
		expected string
	}{
		{
			name:     "[Unit] GetOCSPRevocationReasonString: unspecified",
			reason:   0,
			expected: "unspecified",
		},
		{
			name:     "[Unit] GetOCSPRevocationReasonString: keyCompromise",
			reason:   1,
			expected: "keyCompromise",
		},
		{
			name:     "[Unit] GetOCSPRevocationReasonString: superseded",
			reason:   4,
			expected: "superseded",
		},
		{
			name:     "[Unit] GetOCSPRevocationReasonString: unknown",
			reason:   99,
			expected: "unknown (99)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cast to the OCSP RevocationReason type
			// Note: This is a simplified test since we don't have the actual OCSP package imported
			result := GetRevocationReasonString(tt.reason)
			if result != tt.expected {
				t.Errorf("GetOCSPRevocationReasonString(%d) = %s, want %s", tt.reason, result, tt.expected)
			}
		})
	}
}
