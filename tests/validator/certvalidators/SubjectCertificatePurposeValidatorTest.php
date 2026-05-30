<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use web_eid\web_eid_authtoken_validation_php\testutil\Logger;

class SubjectCertificatePurposeValidatorTest extends TestCase
{
    public function testWhenUserCertAuthenticationPurposeExist(): void
    {
        $cert = Certificates::getJaakKristjanEsteid2018Cert();
        $validator = new SubjectCertificatePurposeValidator(new Logger());
        $this->assertNull($validator->validate($cert));
    }
}
