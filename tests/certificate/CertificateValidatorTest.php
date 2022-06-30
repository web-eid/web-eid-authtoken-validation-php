<?php

namespace web_eid\web_eid_authtoken_validation_php\certificate;

use DateTime;
use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotYetValidException;

class CertificateValidatorTest extends TestCase
{

    public function testWhenCertificateDateValid(): void
    {
        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $this->assertNull(CertificateValidator::certificateIsValidOnDate($cert, new DateTime("20.01.2022 16:00:00"), "User"));
    }

    public function testWhenCertificateNotValidYet(): void
    {
        $this->expectException(CertificateNotYetValidException::class);
        $this->expectExceptionMessage("User certificate is not valid yet");

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

}