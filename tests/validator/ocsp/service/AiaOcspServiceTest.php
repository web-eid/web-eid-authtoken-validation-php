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
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
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
        // Same subject DN and public key as the intermediate CA, different serial and issuer.
        self::$crossIntermediate = self::$pki->buildCrossCertificate(
            self::$intermediate,
            self::$pki->buildRootCa("Other Root CA")
        );
        // Same subject DN as the intermediate CA, different key.
        self::$impostorIntermediate = self::$pki->buildImpostorCa(self::$intermediate, self::$root);
        self::$rootDelegatedResponder = self::$pki->buildOcspResponder("Root Delegated OCSP Responder", self::$root);
        self::$responderWithoutEku = self::$pki->buildOcspResponder(
            "No EKU OCSP Responder",
            self::$intermediate,
            false
        );
    }

    public function testWhenResponderIsDelegatedByIssuerAndIntermediateIsSuppliedThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $service = $this->getAiaOcspService(
            self::$intermediate->getCertificate(),
            [self::$intermediate->getCertificate()]
        );
        $service->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());
    }

    public function testWhenIntermediateIsNotSuppliedThenResponderPathBuildingFails(): void
    {
        $this->expectException(CertificateNotTrustedException::class);
        $this->expectExceptionMessage("Certificate CN=Test OCSP Responder is not trusted");

        $service = $this->getAiaOcspService(self::$intermediate->getCertificate(), []);
        $service->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());
    }

    public function testWhenIssuerIsEquivalentCrossCertificateThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        // The subject certificate issuer is represented by an equivalent cross-certificate
        // that has the same subject DN and public key, but a different serial number.
        $service = $this->getAiaOcspService(
            self::$crossIntermediate->getCertificate(),
            [self::$intermediate->getCertificate()]
        );
        $service->validateResponderCertificate(self::$delegatedResponder->getCertificate(), new DateTime());
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

    public function testWhenIssuerIsImpostorWithSameNameButDifferentKeyThenFails(): void
    {
        // The responder chains to the genuine intermediate CA, but the subject certificate
        // issuer is an impostor CA with the same subject DN and a different key, so the
        // CA identity comparison must fail.
        $service = $this->getAiaOcspService(
            self::$impostorIntermediate->getCertificate(),
            [self::$intermediate->getCertificate()]
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

    public function testWhenResponderIsTheIssuingCaItselfThenOcspSigningEkuIsNotRequired(): void
    {
        $this->expectNotToPerformAssertions();

        // The issuing CA signs its own OCSP responses; the intermediate CA certificate
        // does not have the OCSP-signing extended key usage.
        $service = $this->getAiaOcspService(self::$intermediate->getCertificate(), []);
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

    /**
     * @param X509[] $additionalIntermediateCertificates
     */
    private function getAiaOcspService(
        X509 $certificateIssuerCertificate,
        array $additionalIntermediateCertificates,
    ): AiaOcspService {
        $configuration = new AiaOcspServiceConfiguration(
            new UriCollection(),
            new TrustedCertificates([self::$root->getCertificate()])
        );
        return new AiaOcspService(
            $configuration,
            self::$leaf->getCertificate(),
            $certificateIssuerCertificate,
            $additionalIntermediateCertificates
        );
    }
}
