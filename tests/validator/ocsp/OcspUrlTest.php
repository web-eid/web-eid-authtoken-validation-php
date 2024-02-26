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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Uri;

class OcspUrlTest extends TestCase
{
    public function testWhenExtensionValueIsNullThenReturnsNull()
    {
        $mockCertificate = $this->createMock(X509::class);
        $mockCertificate->method("getExtension")->willReturn(null);
        $this->assertNull(OcspUrl::getOcspUri($mockCertificate));
    }

    public function testWhenExtensionValueIsInvalidThenReturnsNull()
    {
        $mockCertificate = $this->createMock(X509::class);
        $mockCertificate->method("getExtension")->willReturn([
            [
                "accessMethod" => "id-ad-ocsp",
                'accessLocation' => ["uniformResourceIdentifier" => pack("c*", ...array(1, 2, 3))]
            ]
        ]);

        // We will get empty uri parts
        $uri = OcspUrl::getOcspUri($mockCertificate);
        $this->assertFalse(Uri::isAbsolute($uri));
        $this->assertEmpty($uri->getScheme());
        $this->assertEmpty($uri->getHost());
    }

    public function testWhenExtensionValueIsNotAiaThenReturnsNull()
    {
        $mockCertificate = $this->createMock(X509::class);
        $mockCertificate->method("getExtension")->willReturn([
            [
                "accessMethod" => "id-ad-ocsp",
                'accessLocation' => ["uniformResourceIdentifier" => pack("c*", ...array(
                    4, 64, 48, 62, 48, 50, 6, 11, 43, 6, 1, 4, 1, -125, -111, 33, 1, 2, 1, 48,
                    35, 48, 33, 6, 8, 43, 6, 1, 5, 5, 7, 2, 1, 22, 21, 104, 116, 116, 112, 115,
                    58, 47, 47, 119, 119, 119, 46, 115, 107, 46, 101, 101, 47, 67, 80, 83, 48,
                    8, 6, 6, 4, 0, -113, 122, 1, 2
                ))]
            ]
        ]);

        // We will get empty uri parts
        $uri = OcspUrl::getOcspUri($mockCertificate);
        $this->assertFalse(Uri::isAbsolute($uri));
        $this->assertEmpty($uri->getScheme());
        $this->assertEmpty($uri->getHost());
    }
}
