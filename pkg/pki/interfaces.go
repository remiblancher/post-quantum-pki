package pki

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"
)

// CAManager defines the interface for Certificate Authority operations.
// This is the main interface for issuing, revoking, and managing certificates.
type CAManager interface {
	// Issue creates a new certificate from a CSR using the specified profile.
	Issue(ctx context.Context, csr []byte, profile string, vars map[string]string) (*x509.Certificate, error)

	// Revoke marks a certificate as revoked by its serial number.
	Revoke(ctx context.Context, serial string, reason RevocationReason) error

	// GenerateCRL creates a Certificate Revocation List.
	GenerateCRL(ctx context.Context) ([]byte, error)

	// GetCertificate retrieves a certificate by serial number.
	GetCertificate(ctx context.Context, serial string) (*x509.Certificate, error)

	// GetCACertificate returns the CA's certificate.
	GetCACertificate() *x509.Certificate

	// Close releases any resources held by the CA.
	Close() error
}

// Store defines the interface for certificate persistence.
// Implementations include FileStore and PostgresStore.
type Store interface {
	// Init initializes the store (creates directories, tables, etc.).
	Init(ctx context.Context) error

	// Exists checks if the store has been initialized.
	Exists() bool

	// SaveCertificate persists a certificate.
	SaveCertificate(ctx context.Context, cert *x509.Certificate) error

	// LoadCertificate retrieves a certificate by serial.
	LoadCertificate(ctx context.Context, serial []byte) (*x509.Certificate, error)

	// ListCertificates returns certificates matching the filter.
	ListCertificates(ctx context.Context, filter CertificateFilter) ([]*x509.Certificate, error)

	// MarkRevoked marks a certificate as revoked.
	MarkRevoked(ctx context.Context, serial []byte, reason RevocationReason, revokedAt int64) error

	// GetRevokedCertificates returns all revoked certificates for CRL generation.
	GetRevokedCertificates(ctx context.Context) ([]RevokedCertificate, error)

	// SaveCRL persists a CRL.
	SaveCRL(ctx context.Context, crl []byte) error

	// LoadCRL retrieves the latest CRL.
	LoadCRL(ctx context.Context) ([]byte, error)
}

// SignerProvider provides cryptographic signers.
// Implementations include software keys and HSM-backed keys.
type SignerProvider interface {
	// GetSigner returns a signer for the given key identifier.
	GetSigner(ctx context.Context, keyID string) (crypto.Signer, error)

	// GenerateKey creates a new key pair with the specified algorithm.
	GenerateKey(ctx context.Context, algo Algorithm, keyID string) (crypto.Signer, error)

	// DeleteKey removes a key.
	DeleteKey(ctx context.Context, keyID string) error
}

// ProfileLoader loads certificate profiles.
type ProfileLoader interface {
	// Load retrieves a profile by name.
	Load(name string) (*Profile, error)

	// List returns all available profile names.
	List() ([]string, error)
}

// Signer extends crypto.Signer with algorithm information.
type Signer interface {
	crypto.Signer

	// Algorithm returns the algorithm identifier for this signer.
	Algorithm() Algorithm
}

// AuditWriter logs PKI operations for compliance.
type AuditWriter interface {
	// Write logs an audit event.
	Write(ctx context.Context, event AuditEvent) error

	io.Closer
}
