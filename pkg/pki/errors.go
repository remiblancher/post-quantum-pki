package pki

import (
	"errors"
	"fmt"
)

// Sentinel errors for common PKI operations.
var (
	// CA errors
	ErrCANotInitialized = errors.New("CA not initialized")
	ErrCAAlreadyExists  = errors.New("CA already exists")
	ErrCAKeyNotFound    = errors.New("CA key not found")

	// Certificate errors
	ErrCertNotFound       = errors.New("certificate not found")
	ErrCertAlreadyRevoked = errors.New("certificate already revoked")
	ErrCertExpired        = errors.New("certificate expired")
	ErrInvalidCSR         = errors.New("invalid CSR")

	// Profile errors
	ErrProfileNotFound = errors.New("profile not found")
	ErrInvalidProfile  = errors.New("invalid profile")
	ErrMissingVariable = errors.New("missing required variable")

	// Key errors
	ErrKeyNotFound      = errors.New("key not found")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
	ErrHSMNotAvailable  = errors.New("HSM not available")

	// Store errors
	ErrStoreNotInitialized = errors.New("store not initialized")
	ErrStoreClosed         = errors.New("store closed")
)

// PKIError wraps errors with additional context.
type PKIError struct {
	Op      string // Operation that failed (e.g., "issue", "revoke")
	Kind    ErrorKind
	Err     error
	Details map[string]interface{}
}

// ErrorKind categorizes errors for HTTP status mapping.
type ErrorKind int

const (
	KindUnknown ErrorKind = iota
	KindNotFound
	KindInvalidInput
	KindConflict
	KindUnauthorized
	KindInternal
	KindUnavailable
)

func (e *PKIError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return e.Op
}

func (e *PKIError) Unwrap() error {
	return e.Err
}

// HTTPStatus returns an appropriate HTTP status code for this error.
func (e *PKIError) HTTPStatus() int {
	switch e.Kind {
	case KindNotFound:
		return 404
	case KindInvalidInput:
		return 400
	case KindConflict:
		return 409
	case KindUnauthorized:
		return 401
	case KindUnavailable:
		return 503
	case KindInternal:
		return 500
	default:
		return 500
	}
}

// NewError creates a new PKIError.
func NewError(op string, kind ErrorKind, err error) *PKIError {
	return &PKIError{
		Op:   op,
		Kind: kind,
		Err:  err,
	}
}

// WithDetails adds context to an error.
func (e *PKIError) WithDetails(details map[string]interface{}) *PKIError {
	e.Details = details
	return e
}

// IsNotFound checks if an error indicates a resource was not found.
func IsNotFound(err error) bool {
	var pkiErr *PKIError
	if errors.As(err, &pkiErr) {
		return pkiErr.Kind == KindNotFound
	}
	return errors.Is(err, ErrCertNotFound) ||
		errors.Is(err, ErrProfileNotFound) ||
		errors.Is(err, ErrKeyNotFound)
}

// IsInvalidInput checks if an error indicates invalid input.
func IsInvalidInput(err error) bool {
	var pkiErr *PKIError
	if errors.As(err, &pkiErr) {
		return pkiErr.Kind == KindInvalidInput
	}
	return errors.Is(err, ErrInvalidCSR) ||
		errors.Is(err, ErrInvalidProfile) ||
		errors.Is(err, ErrInvalidAlgorithm) ||
		errors.Is(err, ErrMissingVariable)
}
