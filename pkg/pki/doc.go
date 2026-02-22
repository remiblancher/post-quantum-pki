// Package pki provides the public API for the QPKI library.
//
// This package exposes stable interfaces and types that can be used by external
// consumers (like qpki-server) without depending on internal implementation details.
//
// # Interfaces
//
// The main interfaces are:
//   - CAManager: manages Certificate Authority operations (issue, revoke, CRL)
//   - Store: abstracts certificate storage (file, database)
//   - SignerProvider: provides cryptographic signers
//   - ProfileLoader: loads certificate profiles
//
// # Types
//
// Domain types wrap internal types to provide a stable API:
//   - Certificate: represents an X.509 certificate
//   - RevocationReason: certificate revocation reasons
//   - Algorithm: cryptographic algorithm identifiers
//
// # Usage
//
// External consumers should import this package instead of internal packages:
//
//	import "github.com/remiblancher/qpki/pkg/pki"
//
//	func main() {
//	    ca := pki.NewCA(store, signer)
//	    cert, err := ca.Issue(ctx, req)
//	}
package pki
