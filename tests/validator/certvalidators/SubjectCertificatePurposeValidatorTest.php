<?php

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;

class SubjectCertificatePurposeValidatorTest extends TestCase
{
    public function testWhenUserCertAuthenticationPurposeExist(): void
    {
        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $validator = new SubjectCertificatePurposeValidator();
        $this->assertNull($validator->validate($cert));
    }

}