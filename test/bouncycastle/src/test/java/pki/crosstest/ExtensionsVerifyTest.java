package pki.crosstest;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RFC 5280 Extension Compliance Tests with BouncyCastle.
 *
 * Verifies X.509 extension encoding and conformance:
 * - Basic Constraints (criticality, CA flag, pathLen)
 * - Key Usage (criticality, bit values)
 * - Extended Key Usage (OID values)
 * - Certificate Policies (CPS URI as IA5String - bug fix verification)
 * - Subject Alternative Name (GeneralNames encoding)
 * - CRL Distribution Points (DistributionPoint encoding)
 * - Authority Information Access (AccessDescription encoding)
 * - Name Constraints (permitted/excluded subtrees)
 * - Subject/Authority Key Identifiers
 */
public class ExtensionsVerifyTest {

    private static final String FIXTURES = "../fixtures";

    // RFC 5280 Extension OIDs
    private static final ASN1ObjectIdentifier OID_BASIC_CONSTRAINTS = Extension.basicConstraints;
    private static final ASN1ObjectIdentifier OID_KEY_USAGE = Extension.keyUsage;
    private static final ASN1ObjectIdentifier OID_EXT_KEY_USAGE = Extension.extendedKeyUsage;
    private static final ASN1ObjectIdentifier OID_CERT_POLICIES = Extension.certificatePolicies;
    private static final ASN1ObjectIdentifier OID_SUBJECT_ALT_NAME = Extension.subjectAlternativeName;
    private static final ASN1ObjectIdentifier OID_CRL_DIST_POINTS = Extension.cRLDistributionPoints;
    private static final ASN1ObjectIdentifier OID_AUTH_INFO_ACCESS = Extension.authorityInfoAccess;
    private static final ASN1ObjectIdentifier OID_NAME_CONSTRAINTS = Extension.nameConstraints;
    private static final ASN1ObjectIdentifier OID_SUBJECT_KEY_ID = Extension.subjectKeyIdentifier;
    private static final ASN1ObjectIdentifier OID_AUTHORITY_KEY_ID = Extension.authorityKeyIdentifier;

    @BeforeAll
    public static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // =========================================================================
    // Certificate Policies Tests (CPS URI IA5String fix verification)
    // =========================================================================

    @Nested
    @DisplayName("Certificate Policies Extension")
    class CertificatePoliciesTests {

        @Test
        @DisplayName("[RFC5280] CPS URI must be IA5String not PrintableString")
        void certificatePolicies_cpsURI_isIA5String() throws Exception {
            // Test with classical CA that has certificate policies
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ca/ca.crt");

            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            if (ext == null) {
                System.out.println("SKIP: Classical CA has no certificatePolicies extension");
                return;
            }

            // Parse the extension
            CertificatePolicies policies = CertificatePolicies.getInstance(ext.getParsedValue());
            assertNotNull(policies, "Should parse CertificatePolicies");

            for (PolicyInformation pi : policies.getPolicyInformation()) {
                ASN1Sequence qualifiers = pi.getPolicyQualifiers();
                if (qualifiers == null) continue;

                for (int i = 0; i < qualifiers.size(); i++) {
                    PolicyQualifierInfo pqi = PolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));

                    // Check if this is a CPS qualifier
                    if (PolicyQualifierId.id_qt_cps.equals(pqi.getPolicyQualifierId())) {
                        ASN1Encodable qualifier = pqi.getQualifier();

                        // CPS URI MUST be IA5String per RFC 5280 Section 4.2.1.4
                        // This test catches the bug where PrintableString was used
                        assertTrue(qualifier instanceof DERIA5String || qualifier instanceof ASN1IA5String,
                            "CPS URI must be IA5String, got: " + qualifier.getClass().getSimpleName());

                        String uri = ((ASN1String) qualifier).getString();
                        System.out.println("CPS URI (IA5String): " + uri);
                        assertTrue(uri.startsWith("http"), "CPS URI should be a valid URL");
                    }
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] Certificate Policies is non-critical")
        void certificatePolicies_isNonCritical() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ca/ca.crt");

            Extension ext = cert.getExtension(OID_CERT_POLICIES);
            if (ext == null) {
                System.out.println("SKIP: No certificatePolicies extension");
                return;
            }

            // Certificate Policies SHOULD NOT be critical for interoperability
            assertFalse(ext.isCritical(),
                "Certificate Policies should not be critical (RFC 5280 4.2.1.4)");
        }
    }

    // =========================================================================
    // Basic Constraints Tests
    // =========================================================================

    @Nested
    @DisplayName("Basic Constraints Extension")
    class BasicConstraintsTests {

        @Test
        @DisplayName("[RFC5280] CA certificate has BasicConstraints critical=true, CA=true")
        void basicConstraints_CA_isCriticalAndTrue() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ca/ca.crt");

            Extension ext = cert.getExtension(OID_BASIC_CONSTRAINTS);
            assertNotNull(ext, "CA must have BasicConstraints");
            assertTrue(ext.isCritical(), "BasicConstraints MUST be critical for CA (RFC 5280 4.2.1.9)");

            BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
            assertTrue(bc.isCA(), "CA certificate must have CA=true");

            System.out.println("BasicConstraints: CA=" + bc.isCA() +
                ", pathLen=" + bc.getPathLenConstraint());
        }

        @Test
        @DisplayName("[RFC5280] End-entity certificate has no CA constraint")
        void basicConstraints_EE_notCA() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_BASIC_CONSTRAINTS);

            if (ext != null) {
                BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
                assertFalse(bc.isCA(), "End-entity must not have CA=true");
            }
            // If no BasicConstraints, that's also valid for EE
        }

        @Test
        @DisplayName("[RFC5280] PathLength encoding is correct")
        void basicConstraints_pathLength_encoding() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ca/ca.crt");

            Extension ext = cert.getExtension(OID_BASIC_CONSTRAINTS);
            if (ext == null) return;

            BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
            BigInteger pathLen = bc.getPathLenConstraint();

            if (pathLen != null) {
                assertTrue(pathLen.intValue() >= 0, "PathLen must be non-negative");
                System.out.println("PathLen constraint: " + pathLen);
            }
        }
    }

    // =========================================================================
    // Key Usage Tests
    // =========================================================================

    @Nested
    @DisplayName("Key Usage Extension")
    class KeyUsageTests {

        @Test
        @DisplayName("[RFC5280] Key Usage is critical for CA")
        void keyUsage_CA_isCritical() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ca/ca.crt");

            Extension ext = cert.getExtension(OID_KEY_USAGE);
            assertNotNull(ext, "CA should have KeyUsage");
            assertTrue(ext.isCritical(), "KeyUsage MUST be critical (RFC 5280 4.2.1.3)");
        }

        @Test
        @DisplayName("[RFC5280] CA has keyCertSign and cRLSign")
        void keyUsage_CA_hasCorrectBits() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ca/ca.crt");

            Extension ext = cert.getExtension(OID_KEY_USAGE);
            if (ext == null) {
                System.out.println("SKIP: No KeyUsage extension");
                return;
            }

            KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());

            // CA must have keyCertSign (bit 5)
            assertTrue(ku.hasUsages(KeyUsage.keyCertSign),
                "CA must have keyCertSign");
            assertTrue(ku.hasUsages(KeyUsage.cRLSign),
                "CA should have cRLSign");

            System.out.println("CA KeyUsage: keyCertSign=" + ku.hasUsages(KeyUsage.keyCertSign) +
                ", cRLSign=" + ku.hasUsages(KeyUsage.cRLSign));
        }

        @Test
        @DisplayName("[RFC5280] All Key Usage bits parse correctly")
        void keyUsage_allBits_parseCorrectly() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_KEY_USAGE);

            if (ext != null) {
                KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());

                // Print all key usage bits
                StringBuilder sb = new StringBuilder("EE KeyUsage:");
                if (ku.hasUsages(KeyUsage.digitalSignature)) sb.append(" digitalSignature");
                if (ku.hasUsages(KeyUsage.nonRepudiation)) sb.append(" nonRepudiation");
                if (ku.hasUsages(KeyUsage.keyEncipherment)) sb.append(" keyEncipherment");
                if (ku.hasUsages(KeyUsage.dataEncipherment)) sb.append(" dataEncipherment");
                if (ku.hasUsages(KeyUsage.keyAgreement)) sb.append(" keyAgreement");
                if (ku.hasUsages(KeyUsage.keyCertSign)) sb.append(" keyCertSign");
                if (ku.hasUsages(KeyUsage.cRLSign)) sb.append(" cRLSign");
                if (ku.hasUsages(KeyUsage.encipherOnly)) sb.append(" encipherOnly");
                if (ku.hasUsages(KeyUsage.decipherOnly)) sb.append(" decipherOnly");

                System.out.println(sb);
            }
        }
    }

    // =========================================================================
    // Subject Alternative Name Tests
    // =========================================================================

    @Nested
    @DisplayName("Subject Alternative Name Extension")
    class SubjectAltNameTests {

        @Test
        @DisplayName("[RFC5280] DNS names are IA5String")
        void subjectAltName_dnsNames_areIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);

            if (ext == null) {
                System.out.println("SKIP: No SAN extension");
                return;
            }

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.dNSName) {
                    ASN1Encodable name = gn.getName();
                    // DNS names must be IA5String
                    assertTrue(name instanceof DERIA5String || name instanceof ASN1IA5String,
                        "DNS name must be IA5String");
                    System.out.println("DNS name (IA5String): " + ((ASN1String) name).getString());
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] Email addresses are IA5String")
        void subjectAltName_email_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            if (ext == null) return;

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.rfc822Name) {
                    ASN1Encodable name = gn.getName();
                    assertTrue(name instanceof DERIA5String || name instanceof ASN1IA5String,
                        "Email must be IA5String");
                    System.out.println("Email (IA5String): " + ((ASN1String) name).getString());
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] IP addresses are OCTET STRING")
        void subjectAltName_ipAddress_isOctetString() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            if (ext == null) return;

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.iPAddress) {
                    ASN1Encodable addr = gn.getName();
                    assertTrue(addr instanceof ASN1OctetString,
                        "IP address must be OCTET STRING");
                    byte[] bytes = ((ASN1OctetString) addr).getOctets();
                    assertTrue(bytes.length == 4 || bytes.length == 16,
                        "IP must be 4 (IPv4) or 16 (IPv6) bytes");
                    System.out.println("IP address: " + formatIP(bytes));
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] URIs are IA5String")
        void subjectAltName_uri_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_SUBJECT_ALT_NAME);
            if (ext == null) return;

            GeneralNames san = GeneralNames.getInstance(ext.getParsedValue());
            for (GeneralName gn : san.getNames()) {
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    ASN1Encodable uri = gn.getName();
                    assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                        "URI must be IA5String");
                    System.out.println("URI (IA5String): " + ((ASN1String) uri).getString());
                }
            }
        }
    }

    // =========================================================================
    // CRL Distribution Points Tests
    // =========================================================================

    @Nested
    @DisplayName("CRL Distribution Points Extension")
    class CRLDistributionPointsTests {

        @Test
        @DisplayName("[RFC5280] CRL DP URIs are IA5String")
        void crlDistPoints_uri_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_CRL_DIST_POINTS);

            if (ext == null) {
                System.out.println("SKIP: No CRLDP extension");
                return;
            }

            CRLDistPoint cdp = CRLDistPoint.getInstance(ext.getParsedValue());
            for (DistributionPoint dp : cdp.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralNames names = GeneralNames.getInstance(dpn.getName());
                    for (GeneralName gn : names.getNames()) {
                        if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            ASN1Encodable uri = gn.getName();
                            assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                                "CRL DP URI must be IA5String");
                            System.out.println("CRL DP URI (IA5String): " + ((ASN1String) uri).getString());
                        }
                    }
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] CRL Distribution Points is non-critical")
        void crlDistPoints_isNonCritical() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) return;

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_CRL_DIST_POINTS);

            if (ext != null) {
                assertFalse(ext.isCritical(),
                    "CRLDP should not be critical (RFC 5280 4.2.1.13)");
            }
        }
    }

    // =========================================================================
    // Authority Information Access Tests
    // =========================================================================

    @Nested
    @DisplayName("Authority Information Access Extension")
    class AuthorityInfoAccessTests {

        @Test
        @DisplayName("[RFC5280] AIA MUST NOT be critical")
        void authorityInfoAccess_isNotCritical() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) return;

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);

            if (ext != null) {
                assertFalse(ext.isCritical(),
                    "AIA MUST NOT be critical (RFC 5280 4.2.2.1)");
            }
        }

        @Test
        @DisplayName("[RFC5280] OCSP URI is IA5String")
        void authorityInfoAccess_ocsp_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);

            if (ext == null) {
                System.out.println("SKIP: No AIA extension");
                return;
            }

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_ocsp.equals(ad.getAccessMethod())) {
                    GeneralName location = ad.getAccessLocation();
                    if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        ASN1Encodable uri = location.getName();
                        assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                            "OCSP URI must be IA5String");
                        System.out.println("OCSP URI (IA5String): " + ((ASN1String) uri).getString());
                    }
                }
            }
        }

        @Test
        @DisplayName("[RFC5280] CA Issuers URI is IA5String")
        void authorityInfoAccess_caIssuers_isIA5String() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) return;

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_AUTH_INFO_ACCESS);
            if (ext == null) return;

            AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ext.getParsedValue());
            for (AccessDescription ad : aia.getAccessDescriptions()) {
                if (AccessDescription.id_ad_caIssuers.equals(ad.getAccessMethod())) {
                    GeneralName location = ad.getAccessLocation();
                    if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        ASN1Encodable uri = location.getName();
                        assertTrue(uri instanceof DERIA5String || uri instanceof ASN1IA5String,
                            "CA Issuers URI must be IA5String");
                        System.out.println("CA Issuers URI (IA5String): " + ((ASN1String) uri).getString());
                    }
                }
            }
        }
    }

    // =========================================================================
    // Extended Key Usage Tests
    // =========================================================================

    @Nested
    @DisplayName("Extended Key Usage Extension")
    class ExtendedKeyUsageTests {

        @Test
        @DisplayName("[RFC5280] EKU OIDs parse correctly")
        void extKeyUsage_oidsParseCorrectly() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) {
                System.out.println("SKIP: No EE certificate found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_EXT_KEY_USAGE);

            if (ext == null) {
                System.out.println("SKIP: No EKU extension");
                return;
            }

            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ext.getParsedValue());
            KeyPurposeId[] purposes = eku.getUsages();

            System.out.println("Extended Key Usage OIDs:");
            for (KeyPurposeId kp : purposes) {
                System.out.println("  - " + kp.getId() + " (" + getEKUName(kp) + ")");
            }

            assertTrue(purposes.length > 0, "EKU should have at least one purpose");
        }

        private String getEKUName(KeyPurposeId kp) {
            if (KeyPurposeId.id_kp_serverAuth.equals(kp)) return "serverAuth";
            if (KeyPurposeId.id_kp_clientAuth.equals(kp)) return "clientAuth";
            if (KeyPurposeId.id_kp_codeSigning.equals(kp)) return "codeSigning";
            if (KeyPurposeId.id_kp_emailProtection.equals(kp)) return "emailProtection";
            if (KeyPurposeId.id_kp_timeStamping.equals(kp)) return "timeStamping";
            if (KeyPurposeId.id_kp_OCSPSigning.equals(kp)) return "OCSPSigning";
            return "unknown";
        }
    }

    // =========================================================================
    // Subject/Authority Key Identifier Tests
    // =========================================================================

    @Nested
    @DisplayName("Key Identifier Extensions")
    class KeyIdentifierTests {

        @Test
        @DisplayName("[RFC5280] Subject Key Identifier is non-critical")
        void subjectKeyIdentifier_isNonCritical() throws Exception {
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ca/ca.crt");

            Extension ext = cert.getExtension(OID_SUBJECT_KEY_ID);
            assertNotNull(ext, "CA should have SKI");
            assertFalse(ext.isCritical(), "SKI MUST NOT be critical (RFC 5280 4.2.1.2)");

            SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(ext.getParsedValue());
            assertNotNull(ski.getKeyIdentifier(), "SKI should have value");
            System.out.println("SKI length: " + ski.getKeyIdentifier().length + " bytes");
        }

        @Test
        @DisplayName("[RFC5280] Authority Key Identifier is non-critical")
        void authorityKeyIdentifier_isNonCritical() throws Exception {
            String eePath = findCredentialCert(FIXTURES + "/classical/ca/credentials");
            if (eePath == null) return;

            X509CertificateHolder cert = loadCertHolder(eePath);
            Extension ext = cert.getExtension(OID_AUTHORITY_KEY_ID);

            if (ext != null) {
                assertFalse(ext.isCritical(), "AKI MUST NOT be critical (RFC 5280 4.2.1.1)");

                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ext.getParsedValue());
                if (aki.getKeyIdentifier() != null) {
                    System.out.println("AKI length: " + aki.getKeyIdentifier().length + " bytes");
                }
            }
        }
    }

    // =========================================================================
    // Name Constraints Tests
    // =========================================================================

    @Nested
    @DisplayName("Name Constraints Extension")
    class NameConstraintsTests {

        @Test
        @DisplayName("[RFC5280] Name Constraints should be critical")
        void nameConstraints_shouldBeCritical() throws Exception {
            // Most fixtures won't have name constraints, but if they do, verify
            X509CertificateHolder cert = loadCertHolder(FIXTURES + "/classical/ca/ca.crt");

            Extension ext = cert.getExtension(OID_NAME_CONSTRAINTS);
            if (ext == null) {
                System.out.println("INFO: No nameConstraints (optional for CA)");
                return;
            }

            assertTrue(ext.isCritical(),
                "nameConstraints SHOULD be critical (RFC 5280 4.2.1.10)");

            org.bouncycastle.asn1.x509.NameConstraints nc =
                org.bouncycastle.asn1.x509.NameConstraints.getInstance(ext.getParsedValue());

            if (nc.getPermittedSubtrees() != null) {
                System.out.println("Permitted subtrees: " + nc.getPermittedSubtrees().length);
            }
            if (nc.getExcludedSubtrees() != null) {
                System.out.println("Excluded subtrees: " + nc.getExcludedSubtrees().length);
            }
        }
    }

    // =========================================================================
    // PQC Certificate Extension Tests
    // =========================================================================

    @Nested
    @DisplayName("PQC Certificate Extensions")
    class PQCExtensionTests {

        @Test
        @DisplayName("[PQC] ML-DSA CA has correct extensions")
        void mldsa_CA_hasCorrectExtensions() throws Exception {
            File caFile = new File(FIXTURES + "/pqc/mldsa/ca/ca.crt");
            if (!caFile.exists()) {
                System.out.println("SKIP: ML-DSA fixtures not found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(caFile.getPath());

            // Basic Constraints
            Extension bc = cert.getExtension(OID_BASIC_CONSTRAINTS);
            assertNotNull(bc, "ML-DSA CA must have BasicConstraints");
            assertTrue(bc.isCritical(), "BasicConstraints must be critical");
            assertTrue(BasicConstraints.getInstance(bc.getParsedValue()).isCA());

            // Key Usage
            Extension ku = cert.getExtension(OID_KEY_USAGE);
            assertNotNull(ku, "ML-DSA CA must have KeyUsage");
            assertTrue(ku.isCritical(), "KeyUsage must be critical");

            System.out.println("ML-DSA CA extensions verified");
        }

        @Test
        @DisplayName("[PQC] Catalyst hybrid CA has correct extensions")
        void catalyst_CA_hasCorrectExtensions() throws Exception {
            File caFile = new File(FIXTURES + "/catalyst/ca/ca.crt");
            if (!caFile.exists()) {
                System.out.println("SKIP: Catalyst fixtures not found");
                return;
            }

            X509CertificateHolder cert = loadCertHolder(caFile.getPath());

            // Basic Constraints
            Extension bc = cert.getExtension(OID_BASIC_CONSTRAINTS);
            assertNotNull(bc, "Catalyst CA must have BasicConstraints");
            assertTrue(bc.isCritical(), "BasicConstraints must be critical");

            // Key Usage
            Extension ku = cert.getExtension(OID_KEY_USAGE);
            assertNotNull(ku, "Catalyst CA must have KeyUsage");
            assertTrue(ku.isCritical(), "KeyUsage must be critical");

            System.out.println("Catalyst CA extensions verified");
        }
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    private X509CertificateHolder loadCertHolder(String path) throws Exception {
        File file = new File(path);
        if (!file.exists()) {
            throw new RuntimeException("Certificate file not found: " + path);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        try (FileInputStream fis = new FileInputStream(file)) {
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            return new X509CertificateHolder(cert.getEncoded());
        }
    }

    private String findCredentialCert(String credentialsDir) {
        File dir = new File(credentialsDir);
        if (!dir.exists() || !dir.isDirectory()) {
            return null;
        }

        File[] subdirs = dir.listFiles(File::isDirectory);
        if (subdirs == null || subdirs.length == 0) {
            return null;
        }

        File certFile = new File(subdirs[0], "certificates.pem");
        if (certFile.exists()) {
            return certFile.getAbsolutePath();
        }
        return null;
    }

    private String formatIP(byte[] bytes) {
        if (bytes.length == 4) {
            return String.format("%d.%d.%d.%d",
                bytes[0] & 0xFF, bytes[1] & 0xFF, bytes[2] & 0xFF, bytes[3] & 0xFF);
        }
        // IPv6
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i += 2) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x%02x", bytes[i] & 0xFF, bytes[i + 1] & 0xFF));
        }
        return sb.toString();
    }
}
