<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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

    public function testWhenOrganizationCertificateThenSubjectGivenNameAndSurnameAreEmptyAndSubjectCNSucceeds(): void
    {
        $cert = Certificates::getOrganizationCert();
        $givenName = CertificateData::getSubjectGivenName($cert);
        $surname = CertificateData::getSubjectSurname($cert);
        $this->assertEmpty($givenName);
        $this->assertEmpty($surname);
        $principalName = CertificateData::getSubjectCN($cert);
        $this->assertEquals("Testijad.ee isikutuvastus", $principalName);
    }
}
