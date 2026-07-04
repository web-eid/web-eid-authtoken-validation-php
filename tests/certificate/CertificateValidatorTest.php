<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\certificate;

use DateTime;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use web_eid\web_eid_authtoken_validation_php\testutil\Dates;
use web_eid\web_eid_authtoken_validation_php\testutil\TestPkiBuilder;
use web_eid\web_eid_authtoken_validation_php\testutil\TestPkiCredential;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotYetValidException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateRevokedException;

class CertificateValidatorTest extends TestCase
{
    // A synthetic certification chain "root -> C -> B -> A -> leaf" for the
    // token-supplied intermediate CA certificate (NFC-128) tests.
    private static TestPkiBuilder $pki;
    private static TestPkiCredential $root;
    private static TestPkiCredential $caC;
    private static TestPkiCredential $caB;
    private static TestPkiCredential $caA;
    private static TestPkiCredential $chainLeaf;

    public static function setUpBeforeClass(): void
    {
        self::$pki = new TestPkiBuilder();
        self::$root = self::$pki->buildRootCa("Test Root CA");
        self::$caC = self::$pki->buildIntermediateCa("Test CA C", self::$root);
        self::$caB = self::$pki->buildIntermediateCa("Test CA B", self::$caC);
        self::$caA = self::$pki->buildIntermediateCa("Test CA A", self::$caB);
        self::$chainLeaf = self::$pki->buildLeaf("Test Leaf", self::$caA);
    }

    protected function tearDown(): void
    {
        Dates::resetMockedCertificateValidatorDate();
    }

    public function testWhenCertificateDateValid(): void
    {
        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $this->assertNull(CertificateValidator::certificateIsValidOnDate($cert, new DateTime("20.01.2022 16:00:00"), "User"));
    }

    public function testWhenCertificateNotValidYet(): void
    {
        $this->expectException(CertificateNotYetValidException::class);
        $this->expectExceptionMessage("User certificate is not yet valid");

        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $this->assertNull(CertificateValidator::certificateIsValidOnDate($cert, new DateTime("20.01.2000 16:00:00"), "User"));
    }

    public function testWhenCertificateExpired(): void
    {
        $this->expectException(CertificateExpiredException::class);
        $this->expectExceptionMessage("User certificate has expired");

        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $this->assertNull(CertificateValidator::certificateIsValidOnDate($cert, new DateTime("20.01.2050 16:00:00"), "User"));
    }

    public function testWhenCertSignedByDirectIssuerThenReturnsIssuerCert(): void
    {
        Dates::setMockedCertificateValidatorDate(new DateTime("2022-01-20 16:00:00"));

        $issuerCA = Certificates::getTestEsteid2018CA();

        $result = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $this->freshJaakKristjanCert(),
            new TrustedCertificates([$issuerCA])
        );

        $this->assertEquals(
            $issuerCA->saveX509($issuerCA->getCurrentCert(), X509::FORMAT_PEM),
            $result->saveX509($result->getCurrentCert(), X509::FORMAT_PEM)
        );
    }

    public function testWhenCertWithThreeLevelChainThenReturnsIssuerNotRootCert(): void
    {
        Dates::setMockedCertificateValidatorDate(new DateTime("2022-01-20 16:00:00"));

        $issuerCA = Certificates::getTestEsteid2018CA();
        $rootCA = Certificates::getTestEsteid2018CAGov();

        $result = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $this->freshJaakKristjanCert(),
            new TrustedCertificates([$issuerCA, $rootCA])
        );

        // The intermediate issuing CA must be returned, not the root CA
        $this->assertEquals(
            $issuerCA->saveX509($issuerCA->getCurrentCert(), X509::FORMAT_PEM),
            $result->saveX509($result->getCurrentCert(), X509::FORMAT_PEM)
        );
        $this->assertNotEquals(
            $rootCA->saveX509($rootCA->getCurrentCert(), X509::FORMAT_PEM),
            $result->saveX509($result->getCurrentCert(), X509::FORMAT_PEM)
        );
    }

    public function testWhenCertNotTrustedThenThrows(): void
    {
        Dates::setMockedCertificateValidatorDate(new DateTime("2022-01-20 16:00:00"));

        $this->expectException(CertificateNotTrustedException::class);

        CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $this->freshJaakKristjanCert(),
            new TrustedCertificates([Certificates::getTestEsteid2015CA()])
        );
    }

    public function testWhenTokenSuppliedIntermediatesCompleteChainThenReturnsDirectIssuer(): void
    {
        $result = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            self::$chainLeaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [self::$caA->getCertificate(), self::$caB->getCertificate(), self::$caC->getCertificate()],
            null,
            new DateTime()
        );

        $this->assertCertificateEquals(self::$caA, $result);
    }

    public function testWhenLeafIssuedDirectlyByTrustAnchorThenReturnsAnchor(): void
    {
        $directLeaf = self::$pki->buildLeaf("Direct Leaf", self::$root);

        $result = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $directLeaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [],
            null,
            new DateTime()
        );

        $this->assertCertificateEquals(self::$root, $result);
    }

    public function testWhenMidChainTrustAnchorThenPathTerminatesAtAnchor(): void
    {
        // The path "leaf -> A -> B" must terminate at the mid-chain anchor C even though
        // the anchor itself is also offered as a token-supplied candidate.
        $result = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            self::$chainLeaf->getCertificate(),
            new TrustedCertificates([self::$caC->getCertificate()]),
            "User",
            [self::$caA->getCertificate(), self::$caB->getCertificate(), self::$caC->getCertificate()],
            null,
            new DateTime()
        );

        $this->assertCertificateEquals(self::$caA, $result);
    }

    public function testWhenIntermediatesAreMissingThenThrows(): void
    {
        $this->expectException(CertificateNotTrustedException::class);
        $this->expectExceptionMessage("Certificate CN=Test Leaf is not trusted");

        CertificateValidator::validateIsValidAndSignedByTrustedCA(
            self::$chainLeaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [],
            null,
            new DateTime()
        );
    }

    public function testWhenIntermediatesInWrongOrderThenPathIsStillBuilt(): void
    {
        $result = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            self::$chainLeaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [self::$caC->getCertificate(), self::$caB->getCertificate(), self::$caA->getCertificate()],
            null,
            new DateTime()
        );

        $this->assertCertificateEquals(self::$caA, $result);
    }

    public function testWhenIssuerCandidateIsNotCaThenThrows(): void
    {
        $endEntity = self::$pki->buildLeaf("Trusted End Entity", self::$root);
        $forgedLeaf = self::$pki->buildLeaf("Forged Leaf", $endEntity);

        $this->expectException(CertificateNotTrustedException::class);
        $this->expectExceptionMessage("Certificate CN=Forged Leaf is not trusted");

        CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $forgedLeaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [$endEntity->getCertificate()],
            null,
            new DateTime()
        );
    }

    public function testWhenFirstIssuerCandidateReachesDeadEndThenTriesAlternativePath(): void
    {
        $untrustedRoot = self::$pki->buildRootCa("Untrusted Root CA");
        $untrustedIntermediate = self::$pki->buildIntermediateCa("Cross-certified CA", $untrustedRoot);
        $trustedIntermediate = self::$pki->buildCrossCertificate($untrustedIntermediate, self::$root);
        $leaf = self::$pki->buildLeaf("Cross-certified Leaf", $untrustedIntermediate);

        $result = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $leaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [$untrustedIntermediate->getCertificate(), $trustedIntermediate->getCertificate()],
            null,
            new DateTime()
        );

        $this->assertCertificateEquals($trustedIntermediate, $result);
    }

    public function testWhenIntermediateIsExpiredThenThrows(): void
    {
        $expiredCaB = self::$pki->buildIntermediateCa("Expired Test CA B", self::$caC, [
            "notBefore" => new DateTime("-2 years"),
            "notAfter" => new DateTime("-1 year"),
        ]);
        $caA = self::$pki->buildIntermediateCa("Test CA A2", $expiredCaB);
        $leaf = self::$pki->buildLeaf("Test Leaf 2", $caA);

        $this->expectException(CertificateNotTrustedException::class);
        $this->expectExceptionMessage("Certificate CN=Test Leaf 2 is not trusted");

        CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $leaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [$caA->getCertificate(), $expiredCaB->getCertificate(), self::$caC->getCertificate()],
            null,
            new DateTime()
        );
    }

    public function testWhenCheckerThrowsForIntermediateThenThrowsNamingOffendingIntermediate(): void
    {
        $checkerException = new CertificateRevokedException("Intermediate CA certificate has been revoked");
        $checker = new class ($checkerException) implements IntermediateRevocationChecker {
            public function __construct(private AuthTokenException $exception)
            {
            }

            public function validateNotRevoked(
                X509 $certificate,
                X509 $issuerCertificate,
                array $additionalIntermediateCertificates,
            ): void {
                if ($certificate->getSubjectDN(X509::DN_STRING) === "CN=Test CA B") {
                    throw $this->exception;
                }
            }
        };

        try {
            CertificateValidator::validateIsValidAndSignedByTrustedCA(
                self::$chainLeaf->getCertificate(),
                new TrustedCertificates([self::$root->getCertificate()]),
                "User",
                [self::$caA->getCertificate(), self::$caB->getCertificate(), self::$caC->getCertificate()],
                $checker,
                new DateTime()
            );
            $this->fail("Expected " . CertificateNotTrustedException::class . " was not thrown");
        } catch (CertificateNotTrustedException $exception) {
            // The exception must name the offending intermediate, not the leaf.
            $this->assertSame("Certificate CN=Test CA B is not trusted", $exception->getMessage());
            $this->assertSame($checkerException, $exception->getPrevious());
        }
    }

    public function testWhenCheckerGivenThenItIsCalledOncePerNonAnchorIntermediateWithDirectIssuer(): void
    {
        $checker = new class implements IntermediateRevocationChecker {
            public array $calls = [];

            public function validateNotRevoked(
                X509 $certificate,
                X509 $issuerCertificate,
                array $additionalIntermediateCertificates,
            ): void {
                $this->calls[] = [
                    $certificate->getSubjectDN(X509::DN_STRING),
                    $issuerCertificate->getSubjectDN(X509::DN_STRING),
                ];
            }
        };

        CertificateValidator::validateIsValidAndSignedByTrustedCA(
            self::$chainLeaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [self::$caA->getCertificate(), self::$caB->getCertificate(), self::$caC->getCertificate()],
            $checker,
            new DateTime()
        );

        // Neither the leaf nor the trust anchor is checked, each intermediate is
        // checked exactly once and is paired with its direct issuer.
        $this->assertSame([
            ["CN=Test CA A", "CN=Test CA B"],
            ["CN=Test CA B", "CN=Test CA C"],
            ["CN=Test CA C", "CN=Test Root CA"],
        ], $checker->calls);
    }

    public function testWhenCheckerIsNullThenNoRevocationCheckingIsDone(): void
    {
        $result = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            self::$chainLeaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "User",
            [self::$caA->getCertificate(), self::$caB->getCertificate(), self::$caC->getCertificate()],
            null,
            new DateTime()
        );

        $this->assertCertificateEquals(self::$caA, $result);
    }

    public function testWhenLeafExpiredThenErrorMessageUsesCertificateSubjectLabel(): void
    {
        $expiredLeaf = self::$pki->buildLeaf("Expired Leaf", self::$caA, [
            "notBefore" => new DateTime("-2 years"),
            "notAfter" => new DateTime("-1 year"),
        ]);

        $this->expectException(CertificateExpiredException::class);
        $this->expectExceptionMessage("Signing certificate has expired");

        CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $expiredLeaf->getCertificate(),
            new TrustedCertificates([self::$root->getCertificate()]),
            "Signing",
            [self::$caA->getCertificate(), self::$caB->getCertificate(), self::$caC->getCertificate()],
            null,
            new DateTime()
        );
    }

    public function testWhenTrustAnchorIsExpiredThenThrowsCertificateExpiredException(): void
    {
        // The trust anchor is not part of the built certification path, so its validity is
        // not checked during path building; the explicit anchor validity check must reject it
        // while the leaf itself is currently valid.
        $expiredRoot = self::$pki->buildRootCa("Expired Root CA", [
            "notBefore" => new DateTime("-2 days"),
            "notAfter" => new DateTime("-1 day"),
        ]);
        $currentLeaf = self::$pki->buildLeaf("Current Leaf", $expiredRoot);

        $this->expectException(CertificateExpiredException::class);
        $this->expectExceptionMessage("Trusted CA certificate has expired");

        CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $currentLeaf->getCertificate(),
            new TrustedCertificates([$expiredRoot->getCertificate()]),
            "User",
            [],
            null,
            new DateTime()
        );
    }

    private function assertCertificateEquals(TestPkiCredential $expected, X509 $actual): void
    {
        $this->assertEquals(
            $expected->getCertificatePem(),
            $actual->saveX509($actual->getCurrentCert(), X509::FORMAT_PEM)
        );
    }

    private function freshJaakKristjanCert(): X509
    {
        // Load a fresh instance so that loadCA() calls from previous tests don't accumulate
        $template = Certificates::getJaakKristjanEsteid2018Cert();
        $fresh = new X509();
        $fresh->loadX509($template->saveX509($template->getCurrentCert(), X509::FORMAT_PEM));
        return $fresh;
    }
}
