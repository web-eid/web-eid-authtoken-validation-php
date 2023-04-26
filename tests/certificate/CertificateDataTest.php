<?php

/*
 * Copyright (c) 2022-2023 Estonian Information System Authority
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

use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use PHPUnit\Framework\TestCase;
use UnexpectedValueException;

class CertificateDataTest extends TestCase
{

    public function testValidateCertificateSubjectFields(): void
    {
        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $this->assertEquals("JÕEORG,JAAK-KRISTJAN,38001085718", CertificateData::getSubjectCN($cert));
        $this->assertEquals("EE", CertificateData::getSubjectCountryCode($cert));
        $this->assertEquals("JAAK-KRISTJAN", CertificateData::getSubjectGivenName($cert));
        $this->assertEquals("JÕEORG", CertificateData::getSubjectSurname($cert));
        $this->assertEquals("PNOEE-38001085718", CertificateData::getSubjectIdCode($cert));
    }

    public function testWhenOrganizationCertificateThenSubjectCNAndIdCodeAndCountryCodeExtractionSucceeds(): void
    {
        $cert = Certificates::getOrganizationCert();
        $this->assertEquals("Testijad.ee isikutuvastus", CertificateData::getSubjectCN($cert));
        $this->assertEquals("12276279", CertificateData::getSubjectIdCode($cert));
        $this->assertEquals("EE", CertificateData::getSubjectCountryCode($cert));
    }

    public function testWhenOrganizationCertificateThenSubjectGivenNameExtractionFails(): void
    {
        $cert = Certificates::getOrganizationCert();
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage("fieldId id-at-givenName not found in certificate subject");
        CertificateData::getSubjectGivenName($cert);
    }

    public function testWhenOrganizationCertificateThenSubjectSurnameExtractionFails(): void
    {
        $cert = Certificates::getOrganizationCert();
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage("fieldId id-at-surname not found in certificate subject");
        CertificateData::getSubjectSurname($cert);
    }

    public function testWhenOrganizationCertificateThenSucceeds(): void
    {
        $cert = Certificates::getOrganizationCert();
        try {
            $principalName = CertificateData::getSubjectSurname($cert) . " " . CertificateData::getSubjectSurname($cert);
        } catch (UnexpectedValueException $e) {
            $principalName = CertificateData::getSubjectCN($cert);
        }
        $this->assertEquals("Testijad.ee isikutuvastus", $principalName);

    }

}
