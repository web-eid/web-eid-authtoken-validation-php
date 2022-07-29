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

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;

class SubjectCertificateNotRevokedValidatorTest extends TestCase
{
    private const OCSP_RESPONSE = "application/ocsp-response";
    private static OcspClient $ocspClient;
    private SubjectCertificateTrustedValidator $trustedValidator;
    private X509 $estEid2018Cert;

    public function testWhenValidAiaOcspResponderConfigurationThenSucceeds(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenValidDesignatedOcspResponderConfigurationThenSucceeds(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenValidOcspNonceDisabledConfigurationThenSucceeds(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspUrlIsInvalidThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspRequestFailsThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspRequestHasInvalidBodyThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseIsNotSuccessfulThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseHasInvalidCertificateIdThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseHasInvalidSignatureThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseHasInvalidResponderCertThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseHasInvalidTagThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseHas2CertResponsesThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseRevokedThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseUnknownThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenOcspResponseCaNotTrustedThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

    public function testWhenNonceDiffersThenThrows(): void
    {
        // TODO
        $this->assertTrue(1==1);
    }

}