package pki

import (
	"testing"
)

// =============================================================================
// OCSPParseRequest Tests
// =============================================================================

func TestU_OCSPParseRequest(t *testing.T) {
	t.Run("[Unit] OCSPParseRequest: invalid data", func(t *testing.T) {
		_, err := OCSPParseRequest([]byte("not valid OCSP data"))
		if err == nil {
			t.Error("OCSPParseRequest() should fail for invalid data")
		}
	})

	t.Run("[Unit] OCSPParseRequest: empty data", func(t *testing.T) {
		_, err := OCSPParseRequest([]byte{})
		if err == nil {
			t.Error("OCSPParseRequest() should fail for empty data")
		}
	})
}

// =============================================================================
// OCSPParseResponse Tests
// =============================================================================

func TestU_OCSPParseResponse(t *testing.T) {
	t.Run("[Unit] OCSPParseResponse: invalid data", func(t *testing.T) {
		_, err := OCSPParseResponse([]byte("not valid OCSP response"))
		if err == nil {
			t.Error("OCSPParseResponse() should fail for invalid data")
		}
	})

	t.Run("[Unit] OCSPParseResponse: empty data", func(t *testing.T) {
		_, err := OCSPParseResponse([]byte{})
		if err == nil {
			t.Error("OCSPParseResponse() should fail for empty data")
		}
	})
}

// =============================================================================
// OCSPNewMalformedResponse Tests
// =============================================================================

func TestU_OCSPNewMalformedResponse(t *testing.T) {
	t.Run("[Unit] OCSPNewMalformedResponse: returns valid response", func(t *testing.T) {
		data, err := OCSPNewMalformedResponse()
		if err != nil {
			t.Fatalf("OCSPNewMalformedResponse() error = %v", err)
		}
		if len(data) == 0 {
			t.Error("OCSPNewMalformedResponse() returned empty data")
		}
	})
}

// =============================================================================
// OCSPNewInternalErrorResponse Tests
// =============================================================================

func TestU_OCSPNewInternalErrorResponse(t *testing.T) {
	t.Run("[Unit] OCSPNewInternalErrorResponse: returns valid response", func(t *testing.T) {
		data, err := OCSPNewInternalErrorResponse()
		if err != nil {
			t.Fatalf("OCSPNewInternalErrorResponse() error = %v", err)
		}
		if len(data) == 0 {
			t.Error("OCSPNewInternalErrorResponse() returned empty data")
		}
	})
}

// =============================================================================
// OCSP Certificate Status Constants Tests
// =============================================================================

func TestU_OCSPCertStatusConstants(t *testing.T) {
	t.Run("[Unit] OCSPCertStatusConstants: are defined", func(t *testing.T) {
		statuses := []OCSPCertStatus{
			OCSPCertStatusGood,
			OCSPCertStatusRevoked,
			OCSPCertStatusUnknown,
		}

		seen := make(map[OCSPCertStatus]bool)
		for _, s := range statuses {
			if seen[s] {
				t.Errorf("OCSPCertStatus %v is duplicated", s)
			}
			seen[s] = true
		}
	})
}

// =============================================================================
// OCSP Response Status Constants Tests
// =============================================================================

func TestU_OCSPResponseStatusConstants(t *testing.T) {
	t.Run("[Unit] OCSPResponseStatusConstants: are defined", func(t *testing.T) {
		statuses := []OCSPResponseStatus{
			OCSPStatusSuccessful,
			OCSPStatusMalformedRequest,
			OCSPStatusInternalError,
			OCSPStatusTryLater,
			OCSPStatusSigRequired,
			OCSPStatusUnauthorized,
		}

		for _, s := range statuses {
			// Just verify constants are accessible
			_ = s
		}
	})
}

// =============================================================================
// OCSP Revocation Reason Constants Tests
// =============================================================================

func TestU_OCSPRevocationReasonConstants(t *testing.T) {
	t.Run("[Unit] OCSPRevocationReasonConstants: are defined", func(t *testing.T) {
		reasons := []OCSPRevocationReason{
			OCSPReasonUnspecified,
			OCSPReasonKeyCompromise,
			OCSPReasonCACompromise,
			OCSPReasonAffiliationChanged,
			OCSPReasonSuperseded,
			OCSPReasonCessationOfOperation,
			OCSPReasonCertificateHold,
			OCSPReasonRemoveFromCRL,
			OCSPReasonPrivilegeWithdrawn,
			OCSPReasonAACompromise,
		}

		for _, r := range reasons {
			// Just verify constants are accessible
			_ = r
		}
	})
}

// =============================================================================
// OCSP Type Aliases Tests
// =============================================================================

func TestU_OCSPTypes(t *testing.T) {
	t.Run("[Unit] OCSPTypes: OCSPResponderConfig can be instantiated", func(t *testing.T) {
		cfg := &OCSPResponderConfig{}
		if cfg == nil {
			t.Error("OCSPResponderConfig should be instantiable")
		}
	})

	t.Run("[Unit] OCSPTypes: OCSPVerifyConfig can be instantiated", func(t *testing.T) {
		cfg := &OCSPVerifyConfig{}
		if cfg == nil {
			t.Error("OCSPVerifyConfig should be instantiable")
		}
	})

	t.Run("[Unit] OCSPTypes: OCSPStatusInfo can be instantiated", func(t *testing.T) {
		info := &OCSPStatusInfo{}
		if info == nil {
			t.Error("OCSPStatusInfo should be instantiable")
		}
	})
}

// =============================================================================
// OCSPNewErrorResponse Tests
// =============================================================================

func TestU_OCSPNewErrorResponse(t *testing.T) {
	tests := []struct {
		name   string
		status OCSPResponseStatus
	}{
		{
			name:   "[Unit] OCSPNewErrorResponse: malformed request",
			status: OCSPStatusMalformedRequest,
		},
		{
			name:   "[Unit] OCSPNewErrorResponse: internal error",
			status: OCSPStatusInternalError,
		},
		{
			name:   "[Unit] OCSPNewErrorResponse: try later",
			status: OCSPStatusTryLater,
		},
		{
			name:   "[Unit] OCSPNewErrorResponse: sig required",
			status: OCSPStatusSigRequired,
		},
		{
			name:   "[Unit] OCSPNewErrorResponse: unauthorized",
			status: OCSPStatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := OCSPNewErrorResponse(tt.status)
			if err != nil {
				t.Fatalf("OCSPNewErrorResponse() error = %v", err)
			}
			if len(data) == 0 {
				t.Error("OCSPNewErrorResponse() returned empty data")
			}
		})
	}
}
