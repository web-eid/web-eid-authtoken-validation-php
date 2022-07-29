<?php

/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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