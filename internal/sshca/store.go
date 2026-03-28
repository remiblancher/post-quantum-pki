// Package sshca implements SSH Certificate Authority functionality.
// It provides SSH certificate issuance, inspection, and revocation (KRL)
// using OpenSSH certificate format (PROTOCOL.certkeys).
package sshca

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Store defines the interface for SSH CA storage.
type Store interface {
	// Init initializes the store directory structure.
	Init(ctx context.Context) error

	// Exists checks if the store is already initialized.
	Exists() bool

	// BasePath returns the base path of the store.
	BasePath() string

	// NextSerial returns the next serial number and increments the counter.
	NextSerial(ctx context.Context) (uint64, error)

	// SaveSSHCert saves an issued SSH certificate.
	SaveSSHCert(ctx context.Context, cert *ssh.Certificate) error

	// LoadSSHCert loads an SSH certificate by serial number.
	LoadSSHCert(ctx context.Context, serial uint64) (*ssh.Certificate, error)

	// SaveCAPublicKey saves the CA public key in authorized_keys format.
	SaveCAPublicKey(ctx context.Context, pubKey ssh.PublicKey) error

	// LoadCAPublicKey loads the CA public key.
	LoadCAPublicKey(ctx context.Context) (ssh.PublicKey, error)

	// SaveCAInfo saves the SSH CA metadata.
	SaveCAInfo(ctx context.Context, info *CAInfo) error

	// LoadCAInfo loads the SSH CA metadata.
	LoadCAInfo(ctx context.Context) (*CAInfo, error)

	// AppendIndex appends a certificate entry to the index.
	AppendIndex(ctx context.Context, entry IndexEntry) error

	// ReadIndex reads all index entries.
	ReadIndex(ctx context.Context) ([]IndexEntry, error)

	// UpdateIndexStatus updates the status of an index entry by serial.
	UpdateIndexStatus(ctx context.Context, serial uint64, status string) error

	// SaveKRL saves a KRL binary to the krl directory.
	SaveKRL(ctx context.Context, data []byte) error

	// LoadKRL loads the KRL binary.
	LoadKRL(ctx context.Context) ([]byte, error)
}

// IndexEntry represents an entry in the SSH certificate index.
type IndexEntry struct {
	Status     string   `json:"status"`      // V=valid, R=revoked
	Serial     uint64   `json:"serial"`
	KeyID      string   `json:"key_id"`
	CertType   string   `json:"cert_type"`   // "user" or "host"
	Principals []string `json:"principals"`
	ValidAfter uint64   `json:"valid_after"`
	ValidBefore uint64  `json:"valid_before"`
}

// FileStore implements Store using the filesystem.
//
// Directory structure:
//
//	{base}/
//	  ├── ssh-ca.meta.json    # CA metadata
//	  ├── ssh-ca.pub          # CA public key (authorized_keys format)
//	  ├── serial              # Next serial number (decimal)
//	  ├── certs/              # Issued certificates
//	  │   └── {serial}-cert.pub
//	  ├── krl/                # Key Revocation Lists
//	  │   └── krl.bin
//	  └── index.json          # Certificate index
type FileStore struct {
	basePath string
	mu       sync.Mutex // protects serial file
}

var _ Store = (*FileStore)(nil)

// NewFileStore creates a new file-based SSH CA store.
func NewFileStore(basePath string) *FileStore {
	return &FileStore{basePath: basePath}
}

// Init initializes the store directory structure.
func (s *FileStore) Init(ctx context.Context) error {
	dirs := []string{
		s.basePath,
		filepath.Join(s.basePath, "certs"),
		filepath.Join(s.basePath, "krl"),
	}

	for _, dir := range dirs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Initialize serial file if it doesn't exist
	serialPath := filepath.Join(s.basePath, "serial")
	if _, err := os.Stat(serialPath); os.IsNotExist(err) {
		if err := os.WriteFile(serialPath, []byte("1\n"), 0644); err != nil {
			return fmt.Errorf("failed to create serial file: %w", err)
		}
	}

	// Initialize index file if it doesn't exist
	indexPath := filepath.Join(s.basePath, "index.json")
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		if err := os.WriteFile(indexPath, []byte("[]\n"), 0644); err != nil {
			return fmt.Errorf("failed to create index file: %w", err)
		}
	}

	return nil
}

// Exists checks if the store is already initialized.
func (s *FileStore) Exists() bool {
	metaPath := filepath.Join(s.basePath, "ssh-ca.meta.json")
	_, err := os.Stat(metaPath)
	return err == nil
}

// BasePath returns the base path of the store.
func (s *FileStore) BasePath() string {
	return s.basePath
}

// NextSerial returns the next serial number and increments the counter.
func (s *FileStore) NextSerial(ctx context.Context) (uint64, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	serialPath := filepath.Join(s.basePath, "serial")
	data, err := os.ReadFile(serialPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read serial file: %w", err)
	}

	serial, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse serial: %w", err)
	}

	// Increment for next use
	next := serial + 1
	if err := os.WriteFile(serialPath, []byte(strconv.FormatUint(next, 10)+"\n"), 0644); err != nil {
		return 0, fmt.Errorf("failed to update serial file: %w", err)
	}

	return serial, nil
}

// SaveSSHCert saves an issued SSH certificate.
func (s *FileStore) SaveSSHCert(ctx context.Context, cert *ssh.Certificate) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	certPath := filepath.Join(s.basePath, "certs", fmt.Sprintf("%d-cert.pub", cert.Serial))
	data := ssh.MarshalAuthorizedKey(cert)

	if err := os.WriteFile(certPath, data, 0644); err != nil {
		return fmt.Errorf("failed to save SSH certificate: %w", err)
	}

	return nil
}

// LoadSSHCert loads an SSH certificate by serial number.
func (s *FileStore) LoadSSHCert(ctx context.Context, serial uint64) (*ssh.Certificate, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	certPath := filepath.Join(s.basePath, "certs", fmt.Sprintf("%d-cert.pub", serial))
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH certificate: %w", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH certificate: %w", err)
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("file does not contain an SSH certificate")
	}

	return cert, nil
}

// SaveCAPublicKey saves the CA public key in authorized_keys format.
func (s *FileStore) SaveCAPublicKey(ctx context.Context, pubKey ssh.PublicKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pubPath := filepath.Join(s.basePath, "ssh-ca.pub")
	data := ssh.MarshalAuthorizedKey(pubKey)
	if err := os.WriteFile(pubPath, data, 0644); err != nil {
		return fmt.Errorf("failed to save CA public key: %w", err)
	}
	return nil
}

// LoadCAPublicKey loads the CA public key.
func (s *FileStore) LoadCAPublicKey(ctx context.Context) (ssh.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pubPath := filepath.Join(s.basePath, "ssh-ca.pub")
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA public key: %w", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA public key: %w", err)
	}

	return pubKey, nil
}

// SaveCAInfo saves the SSH CA metadata.
func (s *FileStore) SaveCAInfo(ctx context.Context, info *CAInfo) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	metaPath := filepath.Join(s.basePath, "ssh-ca.meta.json")
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CA info: %w", err)
	}
	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		return fmt.Errorf("failed to save CA info: %w", err)
	}
	return nil
}

// LoadCAInfo loads the SSH CA metadata.
func (s *FileStore) LoadCAInfo(ctx context.Context) (*CAInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	metaPath := filepath.Join(s.basePath, "ssh-ca.meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA info: %w", err)
	}
	var info CAInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse CA info: %w", err)
	}
	return &info, nil
}

// AppendIndex appends a certificate entry to the index.
func (s *FileStore) AppendIndex(ctx context.Context, entry IndexEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	indexPath := filepath.Join(s.basePath, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("failed to read index: %w", err)
	}

	var entries []IndexEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse index: %w", err)
	}

	entries = append(entries, entry)

	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	if err := os.WriteFile(indexPath, out, 0644); err != nil {
		return fmt.Errorf("failed to write index: %w", err)
	}

	return nil
}

// ReadIndex reads all index entries.
func (s *FileStore) ReadIndex(ctx context.Context) ([]IndexEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	indexPath := filepath.Join(s.basePath, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	var entries []IndexEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse index: %w", err)
	}

	return entries, nil
}

// UpdateIndexStatus updates the status of an index entry by serial.
func (s *FileStore) UpdateIndexStatus(ctx context.Context, serial uint64, status string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	indexPath := filepath.Join(s.basePath, "index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("failed to read index: %w", err)
	}

	var entries []IndexEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("failed to parse index: %w", err)
	}

	found := false
	for i := range entries {
		if entries[i].Serial == serial {
			entries[i].Status = status
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("certificate with serial %d not found in index", serial)
	}

	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal index: %w", err)
	}

	if err := os.WriteFile(indexPath, out, 0644); err != nil {
		return fmt.Errorf("failed to write index: %w", err)
	}

	return nil
}

// SaveKRL saves a KRL binary to the krl directory.
func (s *FileStore) SaveKRL(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	krlPath := filepath.Join(s.basePath, "krl", "krl.bin")
	if err := os.WriteFile(krlPath, data, 0644); err != nil {
		return fmt.Errorf("failed to save KRL: %w", err)
	}
	return nil
}

// LoadKRL loads the KRL binary.
func (s *FileStore) LoadKRL(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	krlPath := filepath.Join(s.basePath, "krl", "krl.bin")
	data, err := os.ReadFile(krlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read KRL: %w", err)
	}
	return data, nil
}

// certTypeString returns "user" or "host" for an SSH certificate type.
func certTypeString(certType uint32) string {
	if certType == ssh.HostCert {
		return "host"
	}
	return "user"
}

// parseCertType parses "user" or "host" into an SSH certificate type constant.
func parseCertType(s string) (uint32, error) {
	switch strings.ToLower(s) {
	case "user":
		return ssh.UserCert, nil
	case "host":
		return ssh.HostCert, nil
	default:
		return 0, fmt.Errorf("invalid SSH certificate type: %s (expected 'user' or 'host')", s)
	}
}

