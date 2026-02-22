package cli

import (
	"math/big"
	"testing"
	"time"

	"github.com/remiblancher/qpki/internal/ocsp"
)

// =============================================================================
// ParseOCSPSerial Tests
// =============================================================================

func TestU_ParseOCSPSerial(t *testing.T) {
	tests := []struct {
		name      string
		serialHex string
		expected  *big.Int
		wantErr   bool
	}{
		{
			name:      "[Unit] ParseOCSPSerial: valid hex",
			serialHex: "0102030405",
			expected:  new(big.Int).SetBytes([]byte{0x01, 0x02, 0x03, 0x04, 0x05}),
			wantErr:   false,
		},
		{
			name:      "[Unit] ParseOCSPSerial: single byte",
			serialHex: "01",
			expected:  big.NewInt(1),
			wantErr:   false,
		},
		{
			name:      "[Unit] ParseOCSPSerial: empty string",
			serialHex: "",
			expected:  big.NewInt(0),
			wantErr:   false,
		},
		{
			name:      "[Unit] ParseOCSPSerial: invalid hex",
			serialHex: "ZZZZ",
			expected:  nil,
			wantErr:   true,
		},
		{
			name:      "[Unit] ParseOCSPSerial: odd length hex",
			serialHex: "123",
			expected:  nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseOCSPSerial(tt.serialHex)

			if tt.wantErr {
				if err == nil {
					t.Error("ParseOCSPSerial() should return error")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseOCSPSerial() error = %v", err)
			}

			if result.Cmp(tt.expected) != 0 {
				t.Errorf("ParseOCSPSerial() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// ParseOCSPCertStatus Tests
// =============================================================================

func TestU_ParseOCSPCertStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected ocsp.CertStatus
		wantErr  bool
	}{
		{
			name:     "[Unit] ParseOCSPCertStatus: good",
			status:   "good",
			expected: ocsp.CertStatusGood,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseOCSPCertStatus: GOOD (uppercase)",
			status:   "GOOD",
			expected: ocsp.CertStatusGood,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseOCSPCertStatus: revoked",
			status:   "revoked",
			expected: ocsp.CertStatusRevoked,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseOCSPCertStatus: unknown",
			status:   "unknown",
			expected: ocsp.CertStatusUnknown,
			wantErr:  false,
		},
		{
			name:     "[Unit] ParseOCSPCertStatus: invalid status",
			status:   "invalid",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "[Unit] ParseOCSPCertStatus: empty string",
			status:   "",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseOCSPCertStatus(tt.status)

			if tt.wantErr {
				if err == nil {
					t.Error("ParseOCSPCertStatus() should return error")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseOCSPCertStatus() error = %v", err)
			}

			if result != tt.expected {
				t.Errorf("ParseOCSPCertStatus() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// ParseOCSPRevocationTime Tests
// =============================================================================

func TestU_ParseOCSPRevocationTime(t *testing.T) {
	tests := []struct {
		name    string
		timeStr string
		wantErr bool
	}{
		{
			name:    "[Unit] ParseOCSPRevocationTime: valid RFC3339",
			timeStr: "2024-01-15T10:30:00Z",
			wantErr: false,
		},
		{
			name:    "[Unit] ParseOCSPRevocationTime: valid with timezone",
			timeStr: "2024-01-15T10:30:00+02:00",
			wantErr: false,
		},
		{
			name:    "[Unit] ParseOCSPRevocationTime: empty string",
			timeStr: "",
			wantErr: false,
		},
		{
			name:    "[Unit] ParseOCSPRevocationTime: invalid format",
			timeStr: "2024-01-15",
			wantErr: true,
		},
		{
			name:    "[Unit] ParseOCSPRevocationTime: invalid time",
			timeStr: "not a time",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseOCSPRevocationTime(tt.timeStr)

			if tt.wantErr {
				if err == nil {
					t.Error("ParseOCSPRevocationTime() should return error")
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseOCSPRevocationTime() error = %v", err)
			}

			// For empty string, should return current time (approximately)
			if tt.timeStr == "" {
				if time.Since(result) > time.Second {
					t.Error("ParseOCSPRevocationTime() with empty string should return current time")
				}
			}
		})
	}
}

func TestU_ParseOCSPRevocationTime_Parsing(t *testing.T) {
	expected, _ := time.Parse(time.RFC3339, "2024-01-15T10:30:00Z")
	result, err := ParseOCSPRevocationTime("2024-01-15T10:30:00Z")
	if err != nil {
		t.Fatalf("ParseOCSPRevocationTime() error = %v", err)
	}

	if !result.Equal(expected) {
		t.Errorf("ParseOCSPRevocationTime() = %v, want %v", result, expected)
	}
}

// =============================================================================
// OCSPSignParams Tests
// =============================================================================

func TestU_OCSPSignParams_Structure(t *testing.T) {
	now := time.Now()
	serial := big.NewInt(12345)

	params := &OCSPSignParams{
		Serial:           serial,
		CertStatus:       ocsp.CertStatusGood,
		RevocationTime:   now,
		RevocationReason: 0,
		Validity:         24 * time.Hour,
	}

	if params.Serial.Cmp(serial) != 0 {
		t.Errorf("OCSPSignParams.Serial = %v, want %v", params.Serial, serial)
	}

	if params.CertStatus != ocsp.CertStatusGood {
		t.Errorf("OCSPSignParams.CertStatus = %v, want good", params.CertStatus)
	}

	if params.Validity != 24*time.Hour {
		t.Errorf("OCSPSignParams.Validity = %v, want 24h", params.Validity)
	}
}
