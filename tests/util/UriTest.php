<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
