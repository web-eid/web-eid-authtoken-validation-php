<?php

namespace web_eid\web_eid_authtoken_validation_php\authtoken;

use PHPUnit\Framework\TestCase;

use UnexpectedValueException;

class WebEidAuthTokenTest extends TestCase
{

    public function testWhenFaultyAuthTokenParameter(): void
    {
        $authTokenJson = '{"unverifiedCertificate": "MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4","algorithm": 1,"signature": "HBjNXIaUskXbfhzYQHvwjKDUWfNu4yxXZh","format": "web-eid:1.0","appVersion": "https://web-eid.eu/web-eid-app/releases/v2.0.0"}';
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage("'algorithm' is integer, string expected");
        new WebEidAuthToken($authTokenJson);
    }

    public function testValidateAuthTokenParameters(): void
    {
        $authTokenJson = '{"unverifiedCertificate": "MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4","algorithm": "RS256","signature": "HBjNXIaUskXbfhzYQHvwjKDUWfNu4yxXZh","format": "web-eid:1.0","appVersion": "https://web-eid.eu/web-eid-app/releases/v2.0.0"}';
        $authToken = new WebEidAuthToken($authTokenJson);
        $this->assertEquals("MIIFozCCA4ugAwIBAgIQHFpdK-zCQsFW4", $authToken->getUnverifiedCertificate());
        $this->assertEquals("RS256", $authToken->getAlgorithm());
        $this->assertEquals("HBjNXIaUskXbfhzYQHvwjKDUWfNu4yxXZh", $authToken->getSignature());
        $this->assertEquals("web-eid:1.0", $authToken->getFormat());
        $this->assertEquals("https://web-eid.eu/web-eid-app/releases/v2.0.0", $authToken->getAppVersion());
    }

    public function testWhenNotAuthToken(): void
    {
        $authToken = new WebEidAuthToken("somestring");
        $this->assertNotTrue($authToken);
    }

}