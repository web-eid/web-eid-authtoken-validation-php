<?php

namespace web_eid\web_eid_authtoken_validation_php\util;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\MalformedUriException;

class UriTest extends TestCase
{
    public function testWhenIsOrNotAbsolute(): void
    {
        $uri = new Uri("https://example.com");
        $this->assertTrue($uri->isAbsolute() == true);
        $uri = new Uri("https://example.com/page.html");
        $this->assertTrue($uri->isAbsolute() == true);
        $uri = new Uri("http://example.com/page.php?a=1");
        $this->assertTrue($uri->isAbsolute() == true);
        $uri = new Uri("//example.com");
        $this->assertTrue($uri->isAbsolute() == false);
        $uri = new Uri("/page.php");
        $this->assertTrue($uri->isAbsolute() == false);
        $uri = new Uri("./page.html");
        $this->assertTrue($uri->isAbsolute() == false);
        $uri = new Uri("page.html");
        $this->assertTrue($uri->isAbsolute() == false);
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
        $this->assertEquals("usr", $uri->getUser());
        $this->assertEquals("pss", $uri->getPassword());
    }

    public function testVerifyComponents(): void
    {
        $uri = new Uri("https://usr:pss@example.com:81/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $this->assertTrue($uri->verifyComponents(['scheme' => 'https', 'host' => 'example.com', 'port' => 81]) == true);
        $uri = new Uri("http://example.com/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $this->assertTrue($uri->verifyComponents(['scheme' => 'http', 'host' => 'example.com']) == true);
        $uri = new Uri("https://example.com/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $this->assertTrue($uri->verifyComponents(['scheme' => 'https', 'host' => 'example.com', 'port' => 81]) == false);
    }

    public function testWhenNotExactlySameReference(): void
    {
        $uri = new Uri("https://example.com:81/path/index.html?a=b&b[]=2&b[]=3#fragment");
        $reference = $uri->createFromArray([
            'scheme' => 'https',
            'host' => $uri->getHost(),
            'port' => $uri->getPort()
        ]);
        $this->assertNotEquals($uri->getUrl(), $reference->getUrl());
    }
    
}