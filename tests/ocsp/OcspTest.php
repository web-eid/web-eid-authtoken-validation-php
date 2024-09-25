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

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp;

use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\ocsp\certificate\CertificateLoader;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspCertificateException;

class OcspTest extends TestCase
{

    public function testWhenGenerateCertificateIdIsSuccess(): void
    {
        $result = (new Ocsp)->generateCertificateId((new CertificateLoader)->fromFile(__DIR__ . '/../_resources/revoked.crt')->getCert(), (new CertificateLoader)->fromFile(__DIR__ . '/../_resources/revoked.issuer.crt')->getCert());

        $this->assertEquals("1.3.14.3.2.26", $result['hashAlgorithm']['algorithm']);
        $this->assertEquals([126, 230, 106, 231, 114, 154, 179, 252, 248, 162, 32, 100, 108, 22, 161, 45, 96, 113, 8, 93], array_values(unpack('C*', $result['issuerNameHash'])));
        $this->assertEquals([168, 74, 106, 99, 4, 125, 221, 186, 230, 209, 57, 183, 166, 69, 101, 239, 243, 168, 236, 161], array_values(unpack('C*', $result['issuerKeyHash'])));
    }

    public function testWhenMissingSerialNumberInSubjectCertificateThrow(): void
    {

        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage("Serial number of subject certificate does not exist");

        $subject = new X509();
        $subject->setDNProp('id-at-organizationName', 'no serialnumber cert');

        $issuer = new X509();
        $issuer->setDN($subject->getDN());

        (new Ocsp)->generateCertificateId($subject, $issuer);
    }
}
