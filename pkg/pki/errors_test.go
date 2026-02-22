package pki

import (
	"errors"
	"testing"
)

// =============================================================================
// PKIError Tests
// =============================================================================

func TestU_PKIError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *PKIError
		expected string
	}{
		{
			name: "[Unit] PKIError: with wrapped error",
			err: &PKIError{
				Op:  "issue",
				Err: errors.New("test error"),
			},
			expected: "issue: test error",
		},
		{
			name: "[Unit] PKIError: without wrapped error",
			err: &PKIError{
				Op: "revoke",
			},
			expected: "revoke",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("PKIError.Error() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestU_PKIError_Unwrap(t *testing.T) {
	t.Run("[Unit] PKIError: Unwrap returns wrapped error", func(t *testing.T) {
		inner := errors.New("inner error")
		err := &PKIError{
			Op:  "test",
			Err: inner,
		}

		if err.Unwrap() != inner {
			t.Error("PKIError.Unwrap() did not return wrapped error")
		}
	})

	t.Run("[Unit] PKIError: Unwrap returns nil when no wrapped error", func(t *testing.T) {
		err := &PKIError{
			Op: "test",
		}

		if err.Unwrap() != nil {
			t.Error("PKIError.Unwrap() should return nil")
		}
	})
}

// =============================================================================
// HTTPStatus Tests
// =============================================================================

func TestU_PKIError_HTTPStatus(t *testing.T) {
	tests := []struct {
		name     string
		kind     ErrorKind
		expected int
	}{
		{
			name:     "[Unit] HTTPStatus: KindNotFound returns 404",
			kind:     KindNotFound,
			expected: 404,
		},
		{
			name:     "[Unit] HTTPStatus: KindInvalidInput returns 400",
			kind:     KindInvalidInput,
			expected: 400,
		},
		{
			name:     "[Unit] HTTPStatus: KindConflict returns 409",
			kind:     KindConflict,
			expected: 409,
		},
		{
			name:     "[Unit] HTTPStatus: KindUnauthorized returns 401",
			kind:     KindUnauthorized,
			expected: 401,
		},
		{
			name:     "[Unit] HTTPStatus: KindUnavailable returns 503",
			kind:     KindUnavailable,
			expected: 503,
		},
		{
			name:     "[Unit] HTTPStatus: KindInternal returns 500",
			kind:     KindInternal,
			expected: 500,
		},
		{
			name:     "[Unit] HTTPStatus: KindUnknown returns 500",
			kind:     KindUnknown,
			expected: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &PKIError{
				Op:   "test",
				Kind: tt.kind,
			}
			result := err.HTTPStatus()
			if result != tt.expected {
				t.Errorf("PKIError.HTTPStatus() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// NewError Tests
// =============================================================================

func TestU_NewError(t *testing.T) {
	t.Run("[Unit] NewError: creates error with fields", func(t *testing.T) {
		inner := errors.New("inner")
		err := NewError("operation", KindNotFound, inner)

		if err.Op != "operation" {
			t.Errorf("NewError() Op = %s, want operation", err.Op)
		}
		if err.Kind != KindNotFound {
			t.Errorf("NewError() Kind = %v, want KindNotFound", err.Kind)
		}
		if err.Err != inner {
			t.Error("NewError() Err does not match")
		}
	})
}

// =============================================================================
// WithDetails Tests
// =============================================================================

func TestU_PKIError_WithDetails(t *testing.T) {
	t.Run("[Unit] WithDetails: adds details to error", func(t *testing.T) {
		err := &PKIError{
			Op:   "test",
			Kind: KindNotFound,
		}

		details := map[string]interface{}{
			"serial": "abc123",
			"count":  42,
		}

		result := err.WithDetails(details)

		if result != err {
			t.Error("WithDetails() should return the same error")
		}
		if len(err.Details) != 2 {
			t.Errorf("WithDetails() Details length = %d, want 2", len(err.Details))
		}
		if err.Details["serial"] != "abc123" {
			t.Errorf("WithDetails() serial = %v, want abc123", err.Details["serial"])
		}
	})
}

// =============================================================================
// IsNotFound Tests
// =============================================================================

func TestU_IsNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "[Unit] IsNotFound: PKIError with KindNotFound",
			err:      &PKIError{Op: "test", Kind: KindNotFound},
			expected: true,
		},
		{
			name:     "[Unit] IsNotFound: PKIError with other kind",
			err:      &PKIError{Op: "test", Kind: KindInvalidInput},
			expected: false,
		},
		{
			name:     "[Unit] IsNotFound: ErrCertNotFound",
			err:      ErrCertNotFound,
			expected: true,
		},
		{
			name:     "[Unit] IsNotFound: ErrProfileNotFound",
			err:      ErrProfileNotFound,
			expected: true,
		},
		{
			name:     "[Unit] IsNotFound: ErrKeyNotFound",
			err:      ErrKeyNotFound,
			expected: true,
		},
		{
			name:     "[Unit] IsNotFound: unrelated error",
			err:      errors.New("random error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNotFound(tt.err)
			if result != tt.expected {
				t.Errorf("IsNotFound() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// IsInvalidInput Tests
// =============================================================================

func TestU_IsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "[Unit] IsInvalidInput: PKIError with KindInvalidInput",
			err:      &PKIError{Op: "test", Kind: KindInvalidInput},
			expected: true,
		},
		{
			name:     "[Unit] IsInvalidInput: PKIError with other kind",
			err:      &PKIError{Op: "test", Kind: KindNotFound},
			expected: false,
		},
		{
			name:     "[Unit] IsInvalidInput: ErrInvalidCSR",
			err:      ErrInvalidCSR,
			expected: true,
		},
		{
			name:     "[Unit] IsInvalidInput: ErrInvalidProfile",
			err:      ErrInvalidProfile,
			expected: true,
		},
		{
			name:     "[Unit] IsInvalidInput: ErrInvalidAlgorithm",
			err:      ErrInvalidAlgorithm,
			expected: true,
		},
		{
			name:     "[Unit] IsInvalidInput: ErrMissingVariable",
			err:      ErrMissingVariable,
			expected: true,
		},
		{
			name:     "[Unit] IsInvalidInput: unrelated error",
			err:      errors.New("random error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsInvalidInput(tt.err)
			if result != tt.expected {
				t.Errorf("IsInvalidInput() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// =============================================================================
// Sentinel Errors Tests
// =============================================================================

func TestU_SentinelErrors(t *testing.T) {
	t.Run("[Unit] SentinelErrors: are distinct", func(t *testing.T) {
		sentinels := []error{
			ErrCANotInitialized,
			ErrCAAlreadyExists,
			ErrCAKeyNotFound,
			ErrCertNotFound,
			ErrCertAlreadyRevoked,
			ErrCertExpired,
			ErrInvalidCSR,
			ErrProfileNotFound,
			ErrInvalidProfile,
			ErrMissingVariable,
			ErrKeyNotFound,
			ErrInvalidAlgorithm,
			ErrHSMNotAvailable,
			ErrStoreNotInitialized,
			ErrStoreClosed,
		}

		for i, e1 := range sentinels {
			for j, e2 := range sentinels {
				if i != j && errors.Is(e1, e2) {
					t.Errorf("Sentinel errors should be distinct: %v == %v", e1, e2)
				}
			}
		}
	})

	t.Run("[Unit] SentinelErrors: have non-empty messages", func(t *testing.T) {
		sentinels := []error{
			ErrCANotInitialized,
			ErrCertNotFound,
			ErrProfileNotFound,
			ErrKeyNotFound,
		}

		for _, err := range sentinels {
			if err.Error() == "" {
				t.Errorf("Sentinel error should have non-empty message: %v", err)
			}
		}
	})
}

// =============================================================================
// ErrorKind Constants Tests
// =============================================================================

func TestU_ErrorKindConstants(t *testing.T) {
	t.Run("[Unit] ErrorKind: constants are distinct", func(t *testing.T) {
		kinds := []ErrorKind{
			KindUnknown,
			KindNotFound,
			KindInvalidInput,
			KindConflict,
			KindUnauthorized,
			KindInternal,
			KindUnavailable,
		}

		seen := make(map[ErrorKind]bool)
		for _, k := range kinds {
			if seen[k] {
				t.Errorf("ErrorKind %v is duplicated", k)
			}
			seen[k] = true
		}
	})
}
