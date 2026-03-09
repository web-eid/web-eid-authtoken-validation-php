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
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotYetValidException;

class CertificateValidatorTest extends TestCase
{

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

    private function freshJaakKristjanCert(): X509
    {
        // Load a fresh instance so that loadCA() calls from previous tests don't accumulate
        $template = Certificates::getJaakKristjanEsteid2018Cert();
        $fresh = new X509();
        $fresh->loadX509($template->saveX509($template->getCurrentCert(), X509::FORMAT_PEM));
        return $fresh;
    }
}
