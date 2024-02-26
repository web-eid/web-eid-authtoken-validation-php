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

namespace web_eid\web_eid_authtoken_validation_php\util;

use GuzzleHttp\Psr7\Uri;
use PHPUnit\Framework\TestCase;
use TypeError;
use web_eid\web_eid_authtoken_validation_php\testutil\Certificates;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificatePolicyValidator;

class CollectionsUtilTest extends TestCase
{
    public function testUriCollection(): void
    {
        $uri = new Uri("https://page1.com");
        $uriCollection = new UriCollection($uri, new Uri("https://page2.com"));
        $this->assertEquals(2, count($uriCollection->getUrlsArray()));
        $this->assertEquals(2, count($uriCollection->getUrls()));
        $this->assertEquals(2, $uriCollection->count());
        $this->assertTrue($uriCollection->offsetExists(1));
        $this->assertFalse($uriCollection->offsetExists(2));
        $this->assertSame($uri, $uriCollection->offsetGet(0));
        $uriCollection->offsetSet(2, new Uri("https://page3.com"));
        $this->assertEquals(3, $uriCollection->count());
        $uriCollection->offsetUnset(2);
        $this->assertEquals(2, $uriCollection->count());
    }

    public function testGetSubjectDns(): void
    {
        $x509Collection = X509Collection::getSubjectDNs(null, Certificates::getTestEsteid2018CA());
        $this->assertEquals("C=EE, O=SK ID Solutions AS/2.5.4.97=NTREE-10747013, CN=TEST of ESTEID2018", $x509Collection[0]);
    }

    public function testWhenUriIsWrongTypeThenThrows(): void
    {
        $this->expectException(TypeError::class);
        $uriCollection = new UriCollection(new Uri("https://page.com"));
        $uriCollection->offsetSet(1, "Wrong Type");
    }

    public function testWhenX509IsWrongTypeThenThrows(): void
    {
        $this->expectException(TypeError::class);
        $x509Collection = new X509Collection(Certificates::getJaakKristjanEsteid2018Cert());
        $x509Collection->offsetSet(1, "Wrong Type");
    }

    public function testWhenSubjectCertificateValidatorIsWrongTypeThenThrows(): void
    {
        $this->expectException(TypeError::class);
        $subjectCertificateValidatorCollection = new SubjectCertificateValidatorCollection(new SubjectCertificatePolicyValidator(["1.3.6.1.4.1.51361.1.2.1"]));
        $subjectCertificateValidatorCollection->offsetSet(1, "Wrong Type");
    }

}
