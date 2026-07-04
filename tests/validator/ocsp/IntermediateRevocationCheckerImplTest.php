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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use DateTime;
use GuzzleHttp\Psr7\Uri;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateRevocationCheckFailedException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateRevokedException;
use web_eid\web_eid_authtoken_validation_php\ocsp\Ocsp;
use web_eid\web_eid_authtoken_validation_php\ocsp\OcspResponse;
use web_eid\web_eid_authtoken_validation_php\testutil\TestPkiBuilder;
use web_eid\web_eid_authtoken_validation_php\testutil\TestPkiCredential;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use web_eid\web_eid_authtoken_validation_php\util\UriCollection;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;

/**
 * Tests the OCSP-preferred, CRL-fallback revocation checking of token-supplied
 * intermediate CA certificates with a synthetic PKI and fake OCSP/CRL clients.
 */
class IntermediateRevocationCheckerImplTest extends TestCase
{
    private const OCSP_URL = "http://aia.example.com/ocsp";
    private const CRL_URL = "http://crl.example.com/test.crl";
    private const ALLOWED_TIME_SKEW_MINUTES = 15;
    private const MAX_THIS_UPDATE_AGE_MINUTES = 2;

    private static TestPkiBuilder $pki;
    private static TestPkiCredential $root;
    private static TestPkiCredential $caWithoutRevocationSources;
    private static TestPkiCredential $caWithCrl;
    private static TestPkiCredential $caWithOcsp;
    private static TestPkiCredential $caWithOcspAndCrl;
    private static TestPkiCredential $otherCa;
    private static TestPkiCredential $rootDelegatedResponder;

    public static function setUpBeforeClass(): void
    {
        self::$pki = new TestPkiBuilder();
        self::$root = self::$pki->buildRootCa("Test Root CA");
        // The certificates whose revocation status is checked are intermediate CAs
        // issued by the trusted root, with varying revocation source extensions.
        self::$caWithoutRevocationSources = self::$pki->buildIntermediateCa("No Sources CA", self::$root);
        self::$caWithCrl = self::$pki->buildIntermediateCa("CRL CA", self::$root, [
            "crlDistributionPointUrl" => self::CRL_URL,
        ]);
        self::$caWithOcsp = self::$pki->buildIntermediateCa("OCSP CA", self::$root, [
            "aiaOcspUrl" => self::OCSP_URL,
        ]);
        self::$caWithOcspAndCrl = self::$pki->buildIntermediateCa("OCSP and CRL CA", self::$root, [
            "aiaOcspUrl" => self::OCSP_URL,
            "crlDistributionPointUrl" => self::CRL_URL,
        ]);
        self::$otherCa = self::$pki->buildIntermediateCa("Other CA", self::$root);
        self::$rootDelegatedResponder = self::$pki->buildOcspResponder("Root OCSP Responder", self::$root);
    }

    public function testWhenNoOcspUrlAndNoCrlDistributionPointThenThrows(): void
    {
        $this->expectException(CertificateRevocationCheckFailedException::class);
        $this->expectExceptionMessage("no usable OCSP or CRL revocation source");

        $checker = $this->getChecker(self::unusedOcspClient(), self::unusedCrlClient());
        $checker->validateNotRevoked(
            self::$caWithoutRevocationSources->getCertificate(),
            self::$root->getCertificate(),
            []
        );
    }

    public function testWhenCrlDoesNotRevokeCertificateThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $crl = self::$pki->buildCrl(self::$root, [self::$otherCa->getSerialNumber()]);
        $checker = $this->getChecker(self::unusedOcspClient(), self::staticCrlClient($crl));
        $checker->validateNotRevoked(self::$caWithCrl->getCertificate(), self::$root->getCertificate(), []);
    }

    public function testWhenCrlRevokesCertificateThenThrows(): void
    {
        $this->expectException(CertificateRevokedException::class);
        $this->expectExceptionMessage("Intermediate CA certificate has been revoked according to CRL");

        $crl = self::$pki->buildCrl(self::$root, [self::$caWithCrl->getSerialNumber()]);
        $checker = $this->getChecker(self::unusedOcspClient(), self::staticCrlClient($crl));
        $checker->validateNotRevoked(self::$caWithCrl->getCertificate(), self::$root->getCertificate(), []);
    }

    public function testWhenCrlIsSignedByWrongCaThenThrows(): void
    {
        $crl = self::$pki->buildCrl(self::$otherCa, []);
        $checker = $this->getChecker(self::unusedOcspClient(), self::staticCrlClient($crl));

        try {
            $checker->validateNotRevoked(self::$caWithCrl->getCertificate(), self::$root->getCertificate(), []);
            $this->fail("Expected " . CertificateRevocationCheckFailedException::class . " was not thrown");
        } catch (CertificateRevocationCheckFailedException $exception) {
            $this->assertSame(
                "Revocation status of the intermediate CA certificate could not be established",
                $exception->getMessage()
            );
            $this->assertSame(
                "CRL signature verification against the certificate issuer failed",
                $exception->getPrevious()->getMessage()
            );
        }
    }

    public function testWhenCrlIsStaleThenThrows(): void
    {
        $staleCrl = self::$pki->buildCrl(
            self::$root,
            [],
            new DateTime("-2 days"),
            new DateTime("-1 day")
        );
        $checker = $this->getChecker(self::unusedOcspClient(), self::staticCrlClient($staleCrl));

        try {
            $checker->validateNotRevoked(self::$caWithCrl->getCertificate(), self::$root->getCertificate(), []);
            $this->fail("Expected " . CertificateRevocationCheckFailedException::class . " was not thrown");
        } catch (CertificateRevocationCheckFailedException $exception) {
            $this->assertSame(
                "Revocation status of the intermediate CA certificate could not be established",
                $exception->getMessage()
            );
            $this->assertStringContainsString("is in the past", $exception->getPrevious()->getMessage());
        }
    }

    public function testWhenCrlHasNoNextUpdateThenThrows(): void
    {
        $crl = self::$pki->buildCrl(
            self::$root,
            [],
            includeNextUpdate: false
        );
        $checker = $this->getChecker(self::unusedOcspClient(), self::staticCrlClient($crl));

        try {
            $checker->validateNotRevoked(self::$caWithCrl->getCertificate(), self::$root->getCertificate(), []);
            $this->fail("Expected " . CertificateRevocationCheckFailedException::class . " was not thrown");
        } catch (CertificateRevocationCheckFailedException $exception) {
            $this->assertSame(
                "Revocation status of the intermediate CA certificate could not be established",
                $exception->getMessage()
            );
            $this->assertSame("CRL nextUpdate is missing", $exception->getPrevious()->getMessage());
        }
    }

    public function testWhenCrlClientThrowsThenThrows(): void
    {
        $crlClient = new class implements CrlClient {
            public function fetch(Uri $uri): string
            {
                throw new CertificateRevocationCheckFailedException("CRL fetch failed");
            }
        };
        $checker = $this->getChecker(self::unusedOcspClient(), $crlClient);

        try {
            $checker->validateNotRevoked(self::$caWithCrl->getCertificate(), self::$root->getCertificate(), []);
            $this->fail("Expected " . CertificateRevocationCheckFailedException::class . " was not thrown");
        } catch (CertificateRevocationCheckFailedException $exception) {
            $this->assertSame(
                "Revocation status of the intermediate CA certificate could not be established",
                $exception->getMessage()
            );
            $this->assertSame("CRL fetch failed", $exception->getPrevious()->getMessage());
        }
    }

    public function testWhenOcspRespondsGoodThenSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $responseDer = self::$pki->buildOcspResponseDer(
            $this->generateCertificateId(self::$caWithOcsp),
            self::$rootDelegatedResponder,
            "good",
            null,
            null,
            new DateTime("+1 hour")
        );
        $checker = $this->getChecker(self::staticOcspClient($responseDer), self::unusedCrlClient());
        $checker->validateNotRevoked(self::$caWithOcsp->getCertificate(), self::$root->getCertificate(), []);
    }

    public function testWhenOcspRespondsRevokedThenThrowsWithoutCrlFallback(): void
    {
        $responseDer = self::$pki->buildOcspResponseDer(
            $this->generateCertificateId(self::$caWithOcspAndCrl),
            self::$rootDelegatedResponder,
            "revoked"
        );
        // The CRL that does not revoke the certificate must not override the definitive
        // OCSP revoked status.
        $crlWithoutRevocation = self::$pki->buildCrl(self::$root, []);
        $checker = $this->getChecker(
            self::staticOcspClient($responseDer),
            self::staticCrlClient($crlWithoutRevocation)
        );

        $this->expectException(CertificateRevokedException::class);
        $this->expectExceptionMessage("Intermediate CA certificate has been revoked");

        $checker->validateNotRevoked(self::$caWithOcspAndCrl->getCertificate(), self::$root->getCertificate(), []);
    }

    public function testWhenOcspIsInconclusiveThenFallsBackToCrl(): void
    {
        $this->expectNotToPerformAssertions();

        $ocspClient = new class implements OcspClient {
            public function request(Uri $url, string $request): OcspResponse
            {
                throw new RuntimeException("Connection to the OCSP responder failed");
            }
        };
        $crl = self::$pki->buildCrl(self::$root, [self::$otherCa->getSerialNumber()]);
        $checker = $this->getChecker($ocspClient, self::staticCrlClient($crl));
        $checker->validateNotRevoked(self::$caWithOcspAndCrl->getCertificate(), self::$root->getCertificate(), []);
    }

    public function testWhenOcspRespondsUnknownAndNoCrlThenThrows(): void
    {
        $responseDer = self::$pki->buildOcspResponseDer(
            $this->generateCertificateId(self::$caWithOcsp),
            self::$rootDelegatedResponder,
            "unknown"
        );
        $checker = $this->getChecker(self::staticOcspClient($responseDer), self::unusedCrlClient());

        try {
            $checker->validateNotRevoked(self::$caWithOcsp->getCertificate(), self::$root->getCertificate(), []);
            $this->fail("Expected " . CertificateRevocationCheckFailedException::class . " was not thrown");
        } catch (CertificateRevocationCheckFailedException $exception) {
            $this->assertStringContainsString("no usable OCSP or CRL revocation source", $exception->getMessage());
            $this->assertSame(
                "Intermediate CA certificate OCSP status is unknown",
                $exception->getPrevious()->getMessage()
            );
        }
    }

    private function getChecker(OcspClient $ocspClient, CrlClient $crlClient): IntermediateRevocationCheckerImpl
    {
        $configuration = new AiaOcspServiceConfiguration(
            new UriCollection(),
            new TrustedCertificates([self::$root->getCertificate()])
        );
        return new IntermediateRevocationCheckerImpl(
            $ocspClient,
            $crlClient,
            $configuration,
            self::ALLOWED_TIME_SKEW_MINUTES,
            self::MAX_THIS_UPDATE_AGE_MINUTES
        );
    }

    private function generateCertificateId(TestPkiCredential $certificate): array
    {
        return (new Ocsp())->generateCertificateId(
            $certificate->getCertificate(),
            self::$root->getCertificate()
        );
    }

    private static function staticOcspClient(string $responseDer): OcspClient
    {
        return new class ($responseDer) implements OcspClient {
            public function __construct(private string $responseDer)
            {
            }

            public function request(Uri $url, string $request): OcspResponse
            {
                return new OcspResponse($this->responseDer);
            }
        };
    }

    private static function staticCrlClient(string $crlBytes): CrlClient
    {
        return new class ($crlBytes) implements CrlClient {
            public function __construct(private string $crlBytes)
            {
            }

            public function fetch(Uri $uri): string
            {
                return $this->crlBytes;
            }
        };
    }

    private static function unusedOcspClient(): OcspClient
    {
        return new class implements OcspClient {
            public function request(Uri $url, string $request): OcspResponse
            {
                throw new RuntimeException("The OCSP client must not be used in this test");
            }
        };
    }

    private static function unusedCrlClient(): CrlClient
    {
        return new class implements CrlClient {
            public function fetch(Uri $uri): string
            {
                throw new RuntimeException("The CRL client must not be used in this test");
            }
        };
    }
}
