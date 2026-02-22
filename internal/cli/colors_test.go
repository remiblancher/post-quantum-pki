package cli

import (
	"strings"
	"testing"
)

// =============================================================================
// FormatStatus Tests
// =============================================================================

func TestU_FormatStatus(t *testing.T) {
	tests := []struct {
		name           string
		status         string
		expectedColor  string
		expectedStatus string
	}{
		{
			name:           "[Unit] FormatStatus: valid status",
			status:         "valid",
			expectedColor:  ColorGreen,
			expectedStatus: "valid",
		},
		{
			name:           "[Unit] FormatStatus: active status",
			status:         "active",
			expectedColor:  ColorGreen,
			expectedStatus: "active",
		},
		{
			name:           "[Unit] FormatStatus: revoked status",
			status:         "revoked",
			expectedColor:  ColorRed,
			expectedStatus: "revoked",
		},
		{
			name:           "[Unit] FormatStatus: expired status",
			status:         "expired",
			expectedColor:  ColorRed,
			expectedStatus: "expired",
		},
		{
			name:           "[Unit] FormatStatus: invalid status",
			status:         "invalid",
			expectedColor:  ColorRed,
			expectedStatus: "invalid",
		},
		{
			name:           "[Unit] FormatStatus: pending status",
			status:         "pending",
			expectedColor:  ColorYellow,
			expectedStatus: "pending",
		},
		{
			name:           "[Unit] FormatStatus: unknown status",
			status:         "unknown",
			expectedColor:  "",
			expectedStatus: "unknown",
		},
		{
			name:           "[Unit] FormatStatus: empty status",
			status:         "",
			expectedColor:  "",
			expectedStatus: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatStatus(tt.status)

			if tt.expectedColor == "" {
				// For unknown statuses, should return as-is
				if result != tt.expectedStatus {
					t.Errorf("FormatStatus(%q) = %q, want %q", tt.status, result, tt.expectedStatus)
				}
			} else {
				// For known statuses, should contain color codes
				if !strings.Contains(result, tt.expectedColor) {
					t.Errorf("FormatStatus(%q) does not contain expected color code", tt.status)
				}
				if !strings.Contains(result, tt.expectedStatus) {
					t.Errorf("FormatStatus(%q) does not contain status text", tt.status)
				}
				if !strings.Contains(result, ColorReset) {
					t.Errorf("FormatStatus(%q) does not contain reset code", tt.status)
				}
			}
		})
	}
}

// =============================================================================
// Color Constants Tests
// =============================================================================

func TestU_ColorConstants(t *testing.T) {
	tests := []struct {
		name  string
		color string
	}{
		{
			name:  "[Unit] ColorReset is ANSI reset",
			color: ColorReset,
		},
		{
			name:  "[Unit] ColorRed is ANSI red",
			color: ColorRed,
		},
		{
			name:  "[Unit] ColorGreen is ANSI green",
			color: ColorGreen,
		},
		{
			name:  "[Unit] ColorYellow is ANSI yellow",
			color: ColorYellow,
		},
		{
			name:  "[Unit] ColorBlue is ANSI blue",
			color: ColorBlue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// All color codes should start with escape sequence
			if !strings.HasPrefix(tt.color, "\033[") {
				t.Errorf("Color %q does not start with ANSI escape sequence", tt.color)
			}
		})
	}
}
