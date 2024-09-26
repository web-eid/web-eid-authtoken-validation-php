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

use phpseclib3\File\ASN1;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use web_eid\web_eid_authtoken_validation_php\util\AsnUtil;

class OcspRequestTest extends TestCase
{

    private function getRequest(): array
    {
        return [
            'tbsRequest' => [
                'version' => 'v1',
                'requestList' => [],
                'requestExtensions' => [],
            ],
        ];
    }

    private function getNonce(): array
    {
        return [
            'extnId' => AsnUtil::ID_PKIX_OCSP_NONCE,
            'critical' => false,
            'extnValue' => ASN1::encodeDER("nonce", ['type' => ASN1::TYPE_OCTET_STRING]),
        ];
    }

    private function getExpectedRequestWithCertID(): array
    {
        $result = $this->getRequest();
        $result['tbsRequest']['requestList'][] = [
            'reqCert' => [1]
        ];
        return $result;
    }

    private function getExpectedWithNonce(): array
    {
        $result = $this->getRequest();
        $result['tbsRequest']['requestExtensions'][] = $this->getNonce();
        return $result;
    }

    public function testWhenAddCertificateIdSuccess(): void
    {
        $request = new OcspRequest();
        $request->addCertificateId([1]);

        $reflection = new ReflectionClass(get_class($request));
        $property = $reflection->getProperty('ocspRequest');
        $property->setAccessible(true);

        $this->assertEquals($this->getExpectedRequestWithCertID(), $property->getValue($request));
    }

    public function testWhenAddNonceExtensionSuccess(): void
    {
        $request = new OcspRequest();
        $request->addNonceExtension("nonce");

        $reflection = new ReflectionClass(get_class($request));
        $property = $reflection->getProperty('ocspRequest');
        $property->setAccessible(true);

        $this->assertEquals($this->getExpectedWithNonce(), $property->getValue($request));
    }

    public function testWhenGetNonceExtensionSuccess(): void
    {
        $request = new OcspRequest();
        $request->addNonceExtension("nonce");

        $this->assertEquals("nonce", $request->getNonceExtension());
    }
}
