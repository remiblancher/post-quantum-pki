package cli

import (
	"testing"
	"time"

	"github.com/remiblancher/qpki/internal/ca"
)

// =============================================================================
// GetEffectiveStatus Tests
// =============================================================================

func TestU_GetEffectiveStatus(t *testing.T) {
	now := time.Now()
	pastExpiry := now.Add(-24 * time.Hour)
	futureExpiry := now.Add(365 * 24 * time.Hour)

	tests := []struct {
		name     string
		entry    ca.IndexEntry
		expected string
	}{
		{
			name: "[Unit] GetEffectiveStatus: valid certificate",
			entry: ca.IndexEntry{
				Status: "V",
				Expiry: futureExpiry,
			},
			expected: "V",
		},
		{
			name: "[Unit] GetEffectiveStatus: valid but expired",
			entry: ca.IndexEntry{
				Status: "V",
				Expiry: pastExpiry,
			},
			expected: "E",
		},
		{
			name: "[Unit] GetEffectiveStatus: revoked certificate",
			entry: ca.IndexEntry{
				Status: "R",
				Expiry: futureExpiry,
			},
			expected: "R",
		},
		{
			name: "[Unit] GetEffectiveStatus: expired status",
			entry: ca.IndexEntry{
				Status: "E",
			},
			expected: "E",
		},
		{
			name: "[Unit] GetEffectiveStatus: valid with zero expiry",
			entry: ca.IndexEntry{
				Status: "V",
			},
			expected: "V",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetEffectiveStatus(&tt.entry, now)
			if result != tt.expected {
				t.Errorf("GetEffectiveStatus() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// FilterCertEntries Tests
// =============================================================================

func TestU_FilterCertEntries(t *testing.T) {
	now := time.Now()
	futureExpiry := now.Add(365 * 24 * time.Hour)
	pastExpiry := now.Add(-24 * time.Hour)

	entries := []ca.IndexEntry{
		{Serial: []byte{0x01}, Status: "V", Expiry: futureExpiry, Subject: "CN=Valid"},
		{Serial: []byte{0x02}, Status: "V", Expiry: pastExpiry, Subject: "CN=Expired"},
		{Serial: []byte{0x03}, Status: "R", Subject: "CN=Revoked"},
	}

	tests := []struct {
		name     string
		filter   string
		expected int
	}{
		{
			name:     "[Unit] FilterCertEntries: no filter",
			filter:   "",
			expected: 3,
		},
		{
			name:     "[Unit] FilterCertEntries: valid only",
			filter:   "valid",
			expected: 1,
		},
		{
			name:     "[Unit] FilterCertEntries: revoked only",
			filter:   "revoked",
			expected: 1,
		},
		{
			name:     "[Unit] FilterCertEntries: expired only",
			filter:   "expired",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := FilterCertEntries(entries, tt.filter, now)
			if err != nil {
				t.Fatalf("FilterCertEntries() error = %v", err)
			}
			if len(filtered) != tt.expected {
				t.Errorf("FilterCertEntries() returned %d entries, want %d", len(filtered), tt.expected)
			}
		})
	}
}

func TestU_FilterCertEntries_InvalidFilter(t *testing.T) {
	entries := []ca.IndexEntry{
		{Serial: []byte{0x01}, Status: "V"},
	}

	_, err := FilterCertEntries(entries, "invalid", time.Now())
	if err == nil {
		t.Error("FilterCertEntries() should fail for invalid filter")
	}
}

// =============================================================================
// FormatCertEntry Tests
// =============================================================================

func TestU_FormatCertEntry(t *testing.T) {
	now := time.Now()
	expiry := now.Add(365 * 24 * time.Hour)

	t.Run("[Unit] FormatCertEntry: basic formatting", func(t *testing.T) {
		entry := ca.IndexEntry{
			Serial:  []byte{0x01, 0x02, 0x03},
			Status:  "V",
			Expiry:  expiry,
			Subject: "CN=Test",
		}

		status, serial, expiryStr, subject := FormatCertEntry(&entry, now, false)

		if status == "" {
			t.Error("FormatCertEntry() status should not be empty")
		}
		if serial != "010203" {
			t.Errorf("FormatCertEntry() serial = %s, want 010203", serial)
		}
		if expiryStr == "-" {
			t.Error("FormatCertEntry() expiry should not be '-'")
		}
		if subject != "CN=Test" {
			t.Errorf("FormatCertEntry() subject = %s, want CN=Test", subject)
		}
	})

	t.Run("[Unit] FormatCertEntry: long serial truncation", func(t *testing.T) {
		entry := ca.IndexEntry{
			Serial:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
			Status:  "V",
			Expiry:  expiry,
			Subject: "CN=Test",
		}

		_, serial, _, _ := FormatCertEntry(&entry, now, false)

		// Should truncate to 18 chars + ".."
		if len(serial) != 20 {
			t.Errorf("FormatCertEntry() serial length = %d, want 20", len(serial))
		}
	})

	t.Run("[Unit] FormatCertEntry: long subject truncation", func(t *testing.T) {
		longSubject := "CN=This is a very long common name that exceeds fifty characters easily"
		entry := ca.IndexEntry{
			Serial:  []byte{0x01},
			Status:  "V",
			Expiry:  expiry,
			Subject: longSubject,
		}

		_, _, _, subject := FormatCertEntry(&entry, now, false)

		if len(subject) != 50 {
			t.Errorf("FormatCertEntry() subject length = %d, want 50", len(subject))
		}
	})

	t.Run("[Unit] FormatCertEntry: verbose mode no truncation", func(t *testing.T) {
		longSubject := "CN=This is a very long common name that exceeds fifty characters easily"
		entry := ca.IndexEntry{
			Serial:  []byte{0x01},
			Status:  "V",
			Expiry:  expiry,
			Subject: longSubject,
		}

		_, _, _, subject := FormatCertEntry(&entry, now, true)

		if subject != longSubject {
			t.Errorf("FormatCertEntry() subject = %s, want %s", subject, longSubject)
		}
	})

	t.Run("[Unit] FormatCertEntry: zero expiry", func(t *testing.T) {
		entry := ca.IndexEntry{
			Serial:  []byte{0x01},
			Status:  "V",
			Subject: "CN=Test",
		}

		_, _, expiryStr, _ := FormatCertEntry(&entry, now, false)

		if expiryStr != "-" {
			t.Errorf("FormatCertEntry() expiry = %s, want -", expiryStr)
		}
	})
}

// =============================================================================
// FormatStatus for list helpers
// =============================================================================

func TestU_FormatStatus_ListHelpers(t *testing.T) {
	// Test that FormatStatus works correctly with status codes
	tests := []struct {
		status   string
		contains string
	}{
		{"V", "V"},      // Valid
		{"R", "R"},      // Revoked
		{"E", "E"},      // Expired
		{"valid", ""},   // Returns colored
		{"revoked", ""}, // Returns colored
	}

	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			result := FormatStatus(tt.status)
			// Just verify it returns something
			if result == "" {
				t.Errorf("FormatStatus(%s) returned empty string", tt.status)
			}
		})
	}
}
