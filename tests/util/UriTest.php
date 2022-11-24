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

namespace web_eid\web_eid_authtoken_validation_php\util;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use GuzzleHttp\Psr7\Uri;
use PHPUnit\Framework\TestCase;

class UriTest extends TestCase
{
    public function testWhenIsOrNotAbsolute(): void
    {
        $uri = new Uri("https://example.com");
        $this->assertTrue(Uri::isAbsolute($uri) == true);
        $uri = new Uri("https://example.com/page.html");
        $this->assertTrue(Uri::isAbsolute($uri) == true);
        $uri = new Uri("http://example.com/page.php?a=1");
        $this->assertTrue(Uri::isAbsolute($uri) == true);
        $uri = new Uri("//example.com");
        $this->assertTrue(Uri::isAbsolute($uri) == false);
        $uri = new Uri("/page.php");
        $this->assertTrue(Uri::isAbsolute($uri) == false);
        $uri = new Uri("./page.html");
        $this->assertTrue(Uri::isAbsolute($uri) == false);
        $uri = new Uri("page.html");
        $this->assertTrue(Uri::isAbsolute($uri) == false);
    }

    public function testWhenSeriouslyMalformedUriParse(): void
    {
        $this->expectException(MalformedUriException::class);
        new Uri("/search/index.html:2022");
    }

    public function testUriParse(): void
    {
        $uri = new Uri("https://usr:pss@example.com:81/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $this->assertEquals("https", $uri->getScheme());
        $this->assertEquals("example.com", $uri->getHost());
        $this->assertEquals(81, $uri->getPort());
        $this->assertEquals("/path/index.html", $uri->getPath());
        $this->assertEquals("fragment", $uri->getFragment());
        $this->assertEquals("a=b&b[]=2&b[]=3", urldecode($uri->getQuery()));
        $this->assertEquals("usr:pss@example.com:81", $uri->getAuthority());
    }

    public function testVerifyComponents(): void
    {
        $uri = new Uri("https://usr:pss@example.com:81/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $this->assertEquals($uri->getScheme(), "https");
        $this->assertEquals($uri->getHost(), "example.com");
        $this->assertEquals($uri->getPort(), 81);
        $uri = new Uri("http://example.com/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $this->assertEquals($uri->getScheme(), "http");
        $this->assertEquals($uri->getHost(), "example.com");
        $this->assertNull($uri->getPort());
        $this->assertEquals($uri->getFragment(), "fragment");
        $uri = new Uri("https://example.com/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $this->assertEquals($uri->getScheme(), "https");
        $this->assertEquals($uri->getHost(), "example.com");
        $this->assertNull($uri->getPort());
        $this->assertEquals($uri->getQuery(), "a=b&b%5B%5D=2&b%5B%5D=3");
    }

    public function testWhenIsSamePageReference(): void
    {
        $uri = new Uri("https://example.com:81/");
        $isSamePageReference = Uri::isSameDocumentReference(
            $uri,
            Uri::fromParts(
                [
                    "scheme" => "https",  
                    "host" => $uri->getHost(),  
                    "port" => $uri->getPort(),  
                ]
            )
        );
        $this->assertFalse($isSamePageReference);
    }

    public function testWhenNotSamePageReference(): void
    {
        $uri = new Uri("https://example.com:81/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $isSamePageReference = Uri::isSameDocumentReference(
            $uri,
            Uri::fromParts(
                [
                    "scheme" => "https",  
                    "host" => $uri->getHost(),  
                    "port" => $uri->getPort(),  
                ]
            )
        );
        $this->assertFalse($isSamePageReference);
    }
}
