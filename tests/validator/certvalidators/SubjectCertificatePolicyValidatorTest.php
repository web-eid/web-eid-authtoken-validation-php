<?php

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateDisallowedPolicyException;

class SubjectCertificatePolicyValidatorTest extends TestCase
{
    public function testWhenDisallowedPolicyExist(): void
    {

        $this->expectException(UserCertificateDisallowedPolicyException::class);
        $this->expectExceptionMessage("Disallowed user certificate policy");

        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $validator = new SubjectCertificatePolicyValidator(["1.3.6.1.4.1.51361.1.2.1"]);
        $validator->validate($cert);
    }

    public function testWhenDisallowedPolicyNotExist(): void
    {
        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $validator = new SubjectCertificatePolicyValidator(["1.3.6.1.4.1.2.1.2.1"]);
        $this->assertNull($validator->validate($cert));
    }

}