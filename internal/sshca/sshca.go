package sshca

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	pkicrypto "github.com/remiblancher/qpki/internal/crypto"
	"golang.org/x/crypto/ssh"
)

// CAInfo holds SSH CA metadata.
type CAInfo struct {
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm"`
	CertType  string    `json:"cert_type"` // "user" or "host"
	Created   time.Time `json:"created"`
	PublicKey string    `json:"public_key"` // authorized_keys format (fingerprint)
}

// SSHCA represents an SSH Certificate Authority.
type SSHCA struct {
	store     Store
	signer    pkicrypto.Signer
	sshSigner ssh.Signer
	info      *CAInfo
	certType  uint32 // ssh.UserCert or ssh.HostCert
}

// Init initializes a new SSH CA with a generated key pair.
func Init(ctx context.Context, store Store, name string, alg pkicrypto.AlgorithmID, certType string) (*SSHCA, error) {
	if !alg.IsSSHCompatible() {
		return nil, fmt.Errorf("algorithm %s is not supported for SSH certificates", alg)
	}

	ct, err := parseCertType(certType)
	if err != nil {
		return nil, err
	}

	if store.Exists() {
		return nil, fmt.Errorf("SSH CA already exists at %s", store.BasePath())
	}

	// Initialize store directory structure
	if err := store.Init(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize store: %w", err)
	}

	// Generate CA key pair using qpki's key provider
	kp := pkicrypto.NewSoftwareKeyProvider()
	keyPath := store.BasePath() + "/ssh-ca.key"
	signer, err := kp.Generate(alg, pkicrypto.KeyStorageConfig{
		Type:    pkicrypto.KeyProviderTypeSoftware,
		KeyPath: keyPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	// Convert to SSH signer
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}

	// Save CA public key
	if err := store.SaveCAPublicKey(ctx, sshSigner.PublicKey()); err != nil {
		return nil, fmt.Errorf("failed to save CA public key: %w", err)
	}

	// Save CA metadata
	info := &CAInfo{
		Name:      name,
		Algorithm: string(alg),
		CertType:  certType,
		Created:   time.Now().UTC(),
		PublicKey: ssh.FingerprintSHA256(sshSigner.PublicKey()),
	}
	if err := store.SaveCAInfo(ctx, info); err != nil {
		return nil, fmt.Errorf("failed to save CA info: %w", err)
	}

	return &SSHCA{
		store:     store,
		signer:    signer,
		sshSigner: sshSigner,
		info:      info,
		certType:  ct,
	}, nil
}

// Load loads an existing SSH CA from the store.
// The signer must be provided separately (e.g., via KeyProvider.Load).
func Load(ctx context.Context, store Store, signer pkicrypto.Signer) (*SSHCA, error) {
	if !store.Exists() {
		return nil, fmt.Errorf("SSH CA not found at %s", store.BasePath())
	}

	info, err := store.LoadCAInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA info: %w", err)
	}

	ct, err := parseCertType(info.CertType)
	if err != nil {
		return nil, err
	}

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH signer: %w", err)
	}

	return &SSHCA{
		store:     store,
		signer:    signer,
		sshSigner: sshSigner,
		info:      info,
		certType:  ct,
	}, nil
}

// LoadInfo loads SSH CA info without loading the signer (read-only).
func LoadInfo(ctx context.Context, store Store) (*CAInfo, error) {
	return store.LoadCAInfo(ctx)
}

// Info returns the CA metadata.
func (ca *SSHCA) Info() *CAInfo {
	return ca.info
}

// Store returns the CA store.
func (ca *SSHCA) Store() Store {
	return ca.store
}

// PublicKey returns the CA's SSH public key.
func (ca *SSHCA) PublicKey() ssh.PublicKey {
	return ca.sshSigner.PublicKey()
}

// IssueRequest holds the parameters for issuing an SSH certificate.
type IssueRequest struct {
	// PublicKey is the subject's SSH public key to certify.
	PublicKey ssh.PublicKey

	// KeyID is a human-readable identifier for the certificate.
	KeyID string

	// Principals is the list of allowed usernames (user cert) or hostnames (host cert).
	Principals []string

	// ValidAfter is the certificate validity start time.
	// If zero, uses the current time.
	ValidAfter time.Time

	// ValidBefore is the certificate validity end time.
	ValidBefore time.Time

	// CriticalOptions are enforced restrictions (force-command, source-address).
	CriticalOptions map[string]string

	// Extensions are optional permissions (permit-pty, permit-port-forwarding, etc.).
	Extensions map[string]string
}

// Issue issues a new SSH certificate.
func (ca *SSHCA) Issue(ctx context.Context, req IssueRequest) (*ssh.Certificate, error) {
	if req.PublicKey == nil {
		return nil, fmt.Errorf("public key is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key ID is required")
	}
	if len(req.Principals) == 0 {
		return nil, fmt.Errorf("at least one principal is required")
	}
	if req.ValidBefore.IsZero() {
		return nil, fmt.Errorf("validity end time (ValidBefore) is required")
	}

	serial, err := ca.store.NextSerial(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get serial number: %w", err)
	}

	validAfter := req.ValidAfter
	if validAfter.IsZero() {
		validAfter = time.Now().UTC()
	}

	// Build nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	cert := &ssh.Certificate{
		Nonce:           nonce,
		Key:             req.PublicKey,
		Serial:          serial,
		CertType:        ca.certType,
		KeyId:           req.KeyID,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(req.ValidBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: req.CriticalOptions,
			Extensions:      req.Extensions,
		},
	}

	// Sign the certificate with the CA key
	if err := cert.SignCert(rand.Reader, ca.sshSigner); err != nil {
		return nil, fmt.Errorf("failed to sign SSH certificate: %w", err)
	}

	// Save the certificate
	if err := ca.store.SaveSSHCert(ctx, cert); err != nil {
		return nil, fmt.Errorf("failed to save SSH certificate: %w", err)
	}

	// Update index
	entry := IndexEntry{
		Status:      "V",
		Serial:      serial,
		KeyID:       req.KeyID,
		CertType:    certTypeString(ca.certType),
		Principals:  req.Principals,
		ValidAfter:  cert.ValidAfter,
		ValidBefore: cert.ValidBefore,
	}
	if err := ca.store.AppendIndex(ctx, entry); err != nil {
		return nil, fmt.Errorf("failed to update index: %w", err)
	}

	return cert, nil
}

// DefaultUserExtensions returns the default extensions for SSH user certificates.
// These match OpenSSH's default permissions.
func DefaultUserExtensions() map[string]string {
	return map[string]string{
		"permit-pty":              "",
		"permit-user-rc":         "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding": "",
		"permit-X11-forwarding":  "",
	}
}

// DefaultHostExtensions returns the default extensions for SSH host certificates.
// Host certificates have no extensions by default.
func DefaultHostExtensions() map[string]string {
	return nil
}
