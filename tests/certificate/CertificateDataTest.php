<?php

namespace web_eid\web_eid_authtoken_validation_php\certificate;

use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use PHPUnit\Framework\TestCase;

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

}