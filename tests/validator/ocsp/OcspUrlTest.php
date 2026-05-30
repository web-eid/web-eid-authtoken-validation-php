<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use phpseclib3\File\X509;
use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Uri;

class OcspUrlTest extends TestCase
{
    public function testWhenExtensionValueIsNullThenReturnsNull()
    {
        $certificate = $this->createStub(X509::class);
        $certificate->method("getExtension")->willReturn(null);
        $this->assertNull(OcspUrl::getOcspUri($certificate));
    }

    public function testWhenExtensionValueIsInvalidThenReturnsNull()
    {
        $certificate = $this->createStub(X509::class);
        $certificate->method("getExtension")->willReturn([
            [
                "accessMethod" => "id-ad-ocsp",
                'accessLocation' => ["uniformResourceIdentifier" => pack("c*", ...array(1, 2, 3))]
            ]
        ]);

        // We will get empty uri parts
        $uri = OcspUrl::getOcspUri($certificate);
        $this->assertFalse(Uri::isAbsolute($uri));
        $this->assertEmpty($uri->getScheme());
        $this->assertEmpty($uri->getHost());
    }

    public function testWhenExtensionValueIsNotAiaThenReturnsNull()
    {
        $certificate = $this->createStub(X509::class);
        $certificate->method("getExtension")->willReturn([
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
        $uri = OcspUrl::getOcspUri($certificate);
        $this->assertFalse(Uri::isAbsolute($uri));
        $this->assertEmpty($uri->getScheme());
        $this->assertEmpty($uri->getHost());
    }
}
