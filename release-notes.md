## ✨ Features
- **QCStatements extension** for eIDAS qualified certificates (ETSI EN 319 412-5)
  - QcCompliance, QcType (esign/eseal/web), QcSSCD, QcRetentionPeriod, QcPDS
- **Automatic esi4-qtstStatement-1** extension for qualified TSA tokens (ETSI EN 319 422)
- **Custom X.509 extensions** support in profiles
- **Custom OIDs** in extKeyUsage
- **DN string encoding** configuration (UTF-8, PrintableString, IA5String per RFC 5280)

## 🧪 Testing
- Improved test coverage for QCStatements and eIDAS timestamp features
- Round-trip tests for QCStatements encoding/decoding
- Edge case validation for PDS language codes and retention periods

## 📚 Documentation
- Profiles documentation Table of Contents simplified
- eIDAS Qualified Timestamps section added to TSA documentation
- QCStatements extension configuration guide
