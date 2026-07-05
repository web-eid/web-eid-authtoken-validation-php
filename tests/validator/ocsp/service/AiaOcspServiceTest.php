<?php

/*
 * Copyright (c) 2026 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp\service;

use DateTime;
use phpseclib3\File\X509;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\certificate\IntermediateRevocationChecker;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateRevocationCheckFailedException;
use web_eid\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use web_eid\web_eid_authtoken_validation_php\testutil\TestPkiBuilder;
use web_eid\web_eid_authtoken_validation_php\testutil\TestPkiCredential;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use web_eid\web_eid_authtoken_validation_php\util\UriCollection;

/**
 * Tests the AIA OCSP responder certificate authorization checks with a synthetic PKI:
 * the root CA is trusted, the intermediate CA that issued the subject certificate is not
 * configured and must be supplied as a token-provided path-building candidate.
 */
class AiaOcspServiceTest extends TestCase
{
    private const NOT_AUTHORIZED_MESSAGE = "OCSP responder is not authorized by the subject certificate issuer";

    private static TestPkiBuilder $pki;
    private static TestPkiCredential $root;
    private static TestPkiCredential $intermediate;
    private static TestPkiCredential $leaf;
    private static TestPkiCredential $delegatedResponder;
    private static TestPkiCredential $siblingCa;
    private static TestPkiCredential $siblingResponder;
    private static TestPkiCredential $crossIntermediate;
    private static TestPkiCredential $impostorIntermediate;
    private static TestPkiCredential $rootDelegatedResponder;
    private static TestPkiCredential $responderWithoutEku;

    public static function setUpBeforeClass(): void
    {
        self::$pki = new TestPkiBuilder();
        self::$root = self::$pki->buildRootCa("Test Root CA");
        self::$intermediate = self::$pki->buildIntermediateCa("Test Intermediate CA", self::$root);
        self::$leaf = self::$pki->buildLeaf("Test Leaf", self::$intermediate, [
            "aiaOcspUrl" => "http://aia.example.com/ocsp",
        ]);
        self::$delegatedResponder = self::$pki->buildOcspResponder("Test OCSP Responder", self::$intermediate);
        self::$siblingCa = self::$pki->buildIntermediateCa("Test Sibling CA", self::$root);
        self::$siblingResponder = self::$pki->buildOcspResponder("Test Sibling OCSP Responder", self::$siblingCa);
        // An equivalent cross-certificate for the intermediate CA: same subject DN and public
        // key, but a distinct certificate (different serial number), also issued by the trusted
        // root so that it can chain to a trust anchor on its own.
        self::$crossIntermediate = self::$pki->buildCrossCertificate(self::$intermediate, self::$root);
        // Same subject DN as the intermediate CA, different key.
        self::$impostorIntermediate = self::$pki->buildImpostorCa(self::$intermediate, self::$root);
        self::$rootDelegatedResponder = self::$pki->buildOcspResponder("Root Delegated OCSP Responder", self::$root);
        self::$responderWithoutEku = self::$pki->buildOcspResponder(
            "No EKU OCSP Responder",
            self::$intermediate,
            false
        );
    }

    #[DataProvider('matchingPolicies')]
    public function testWhenResponderIsDelegatedByIssuerAndIntermediateIsSuppliedThenSucceeds(
        ResponderIssuerMatchingPolicy $matchingPolicy,
    ): void {
        $this->expectNotToPerformAssertions();

        $service = $this->getAiaOcspService(
            self::$intermediate->getCertificate(),
            [self::$intermediate->getCertificate()],
            $matchingPolicy,
        );
        $service->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());
    }

    public function testWhenMatchingPolicyIsNotSpecifiedThenExactCertificateMatchingIsUsed(): void
    {
        $configuration = new AiaOcspServiceConfiguration(
            new UriCollection(),
            new TrustedCertificates([self::$root->getCertificate()])
        );

        $this->assertSame(
            ResponderIssuerMatchingPolicy::EXACT_CERTIFICATE,
            $configuration->getResponderIssuerMatchingPolicy()
        );
    }

    public function testWhenIntermediateIsNotSuppliedThenResponderPathBuildingFails(): void
    {
        $this->expectException(CertificateNotTrustedException::class);
        $this->expectExceptionMessage("Certificate CN=Test OCSP Responder is not trusted");

        $service = $this->getAiaOcspService(self::$intermediate->getCertificate(), []);
        $service->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());
    }

    public function testWhenIntermediateRevocationStatusIsUnknownThenOnlySubjectAndPublicKeyPolicyFails(): void
    {
        // Simulates an intermediate whose revocation status cannot be established, e.g. because
        // it has no usable OCSP or CRL revocation source.
        $alwaysFailingChecker = new class implements IntermediateRevocationChecker {
            public function validateNotRevoked(
                X509 $certificate,
                X509 $issuerCertificate,
                array $additionalIntermediateCertificates,
            ): void {
                throw new CertificateRevocationCheckFailedException(
                    "Revocation status of the intermediate CA certificate could not be established"
                );
            }
        };

        $exactService = $this->getAiaOcspService(
            self::$intermediate->getCertificate(),
            [self::$intermediate->getCertificate()],
            ResponderIssuerMatchingPolicy::EXACT_CERTIFICATE,
            $alwaysFailingChecker,
        );
        $subjectAndPublicKeyService = $this->getAiaOcspService(
            self::$intermediate->getCertificate(),
            [self::$intermediate->getCertificate()],
            ResponderIssuerMatchingPolicy::SUBJECT_AND_PUBLIC_KEY,
            $alwaysFailingChecker,
        );

        // The exact-certificate policy never checks the responder's own path intermediates, so
        // the always-failing checker is never consulted.
        $exactService->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());

        $this->expectException(CertificateNotTrustedException::class);
        $subjectAndPublicKeyService->validateResponderCertificate(
            self::$delegatedResponder->getCertificate(),
            new DateTime()
        );
    }

    public function testWhenIssuerIsEquivalentCrossCertificateWithDefaultPolicyThenFails(): void
    {
        // The responder still chains to the root via the real intermediate, so its issuer in the
        // built path is the real intermediate. The subject certificate issuer is passed as the
        // equivalent cross-certificate (same subject and public key, different certificate),
        // which the default exact-certificate policy must reject.
        $service = $this->getAiaOcspService(
            self::$crossIntermediate->getCertificate(),
            [self::$intermediate->getCertificate()]
        );

        try {
            $service->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());
            $this->fail("Expected " . CertificateNotTrustedException::class . " was not thrown");
        } catch (CertificateNotTrustedException $exception) {
            $this->assertInstanceOf(OCSPCertificateException::class, $exception->getPrevious());
            $this->assertSame(self::NOT_AUTHORIZED_MESSAGE, $exception->getPrevious()->getMessage());
        }
    }

    public function testWhenIssuerIsEquivalentCrossCertificateWithSubjectAndPublicKeyPolicyThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $service = $this->getAiaOcspService(
            self::$crossIntermediate->getCertificate(),
            [self::$intermediate->getCertificate()],
            ResponderIssuerMatchingPolicy::SUBJECT_AND_PUBLIC_KEY,
        );
        $service->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());
    }

    public function testWhenResponseIsSignedByEquivalentCrossCertificateWithDefaultPolicyThenFails(): void
    {
        $service = $this->getAiaOcspService(self::$intermediate->getCertificate(), []);

        try {
            $service->validateResponderCertificate(self::$crossIntermediate->getCertificate(), new DateTime());
            $this->fail("Expected " . CertificateNotTrustedException::class . " was not thrown");
        } catch (CertificateNotTrustedException $exception) {
            $this->assertInstanceOf(OCSPCertificateException::class, $exception->getPrevious());
            $this->assertStringContainsString(
                "equivalent to but not the same as the subject certificate issuer",
                $exception->getPrevious()->getMessage()
            );
        }
    }

    public function testWhenResponseIsSignedByEquivalentCrossCertificateWithSubjectAndPublicKeyPolicyThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $service = $this->getAiaOcspService(
            self::$intermediate->getCertificate(),
            [],
            ResponderIssuerMatchingPolicy::SUBJECT_AND_PUBLIC_KEY,
        );
        $service->validateResponderCertificate(self::$crossIntermediate->getCertificate(), new DateTime());
    }

    public function testWhenResponderIsDelegatedBySiblingCaThenFails(): void
    {
        $service = $this->getAiaOcspService(
            self::$intermediate->getCertificate(),
            [self::$siblingCa->getCertificate()]
        );

        try {
            $service->validateResponderCertificate(self::$siblingResponder->getCertificate(), new DateTime());
            $this->fail("Expected " . CertificateNotTrustedException::class . " was not thrown");
        } catch (CertificateNotTrustedException $exception) {
            $this->assertSame(
                "Certificate CN=Test Sibling OCSP Responder is not trusted",
                $exception->getMessage()
            );
            $this->assertInstanceOf(OCSPCertificateException::class, $exception->getPrevious());
            $this->assertSame(self::NOT_AUTHORIZED_MESSAGE, $exception->getPrevious()->getMessage());
        }
    }

    #[DataProvider('matchingPolicies')]
    public function testWhenIssuerIsImpostorWithSameNameButDifferentKeyThenFails(
        ResponderIssuerMatchingPolicy $matchingPolicy,
    ): void {
        // The responder chains to the genuine intermediate CA, but the subject certificate
        // issuer is an impostor CA with the same subject DN and a different key, so the
        // CA identity comparison must fail.
        $service = $this->getAiaOcspService(
            self::$impostorIntermediate->getCertificate(),
            [self::$intermediate->getCertificate()],
            $matchingPolicy,
        );

        try {
            $service->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());
            $this->fail("Expected " . CertificateNotTrustedException::class . " was not thrown");
        } catch (CertificateNotTrustedException $exception) {
            $this->assertSame("Certificate CN=Test OCSP Responder is not trusted", $exception->getMessage());
            $this->assertInstanceOf(OCSPCertificateException::class, $exception->getPrevious());
            $this->assertSame(self::NOT_AUTHORIZED_MESSAGE, $exception->getPrevious()->getMessage());
        }
    }

    public function testWhenResponderIsDelegatedByRootInsteadOfIssuerThenFails(): void
    {
        $service = $this->getAiaOcspService(self::$intermediate->getCertificate(), []);

        try {
            $service->validateResponderCertificate(self::$rootDelegatedResponder->getCertificate(), new DateTime());
            $this->fail("Expected " . CertificateNotTrustedException::class . " was not thrown");
        } catch (CertificateNotTrustedException $exception) {
            $this->assertSame(
                "Certificate CN=Root Delegated OCSP Responder is not trusted",
                $exception->getMessage()
            );
            $this->assertInstanceOf(OCSPCertificateException::class, $exception->getPrevious());
            $this->assertSame(self::NOT_AUTHORIZED_MESSAGE, $exception->getPrevious()->getMessage());
        }
    }

    #[DataProvider('matchingPolicies')]
    public function testWhenResponderIsTheIssuingCaItselfThenOcspSigningEkuIsNotRequired(
        ResponderIssuerMatchingPolicy $matchingPolicy,
    ): void {
        $this->expectNotToPerformAssertions();

        // The issuing CA signs its own OCSP responses; the intermediate CA certificate
        // does not have the OCSP-signing extended key usage.
        $service = $this->getAiaOcspService(self::$intermediate->getCertificate(), [], $matchingPolicy);
        $service->validateResponderCertificate(self::$intermediate->getCertificate(), new DateTime());
    }

    public function testWhenDelegatedResponderDoesNotHaveOcspSigningEkuThenThrows(): void
    {
        $this->expectException(OCSPCertificateException::class);
        $this->expectExceptionMessage(
            "Certificate CN=No EKU OCSP Responder does not contain the extended key usage " .
            "extension value for OCSP response signing"
        );

        $service = $this->getAiaOcspService(
            self::$intermediate->getCertificate(),
            [self::$intermediate->getCertificate()]
        );
        $service->validateResponderCertificate(self::$responderWithoutEku->getCertificate(), new DateTime());
    }

    /** @return array<string, array{ResponderIssuerMatchingPolicy}> */
    public static function matchingPolicies(): array
    {
        return [
            "EXACT_CERTIFICATE" => [ResponderIssuerMatchingPolicy::EXACT_CERTIFICATE],
            "SUBJECT_AND_PUBLIC_KEY" => [ResponderIssuerMatchingPolicy::SUBJECT_AND_PUBLIC_KEY],
        ];
    }

    /**
     * @param X509[] $additionalIntermediateCertificates
     */
    private function getAiaOcspService(
        X509 $certificateIssuerCertificate,
        array $additionalIntermediateCertificates,
        ?ResponderIssuerMatchingPolicy $matchingPolicy = null,
        ?IntermediateRevocationChecker $intermediateRevocationChecker = null,
    ): AiaOcspService {
        $configuration = new AiaOcspServiceConfiguration(
            new UriCollection(),
            new TrustedCertificates([self::$root->getCertificate()]),
            $matchingPolicy ?? ResponderIssuerMatchingPolicy::EXACT_CERTIFICATE,
        );
        return new AiaOcspService(
            $configuration,
            self::$leaf->getCertificate(),
            $certificateIssuerCertificate,
            $additionalIntermediateCertificates,
            $intermediateRevocationChecker,
        );
    }
}
