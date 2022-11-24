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

namespace web_eid\web_eid_authtoken_validation_php\authtoken;

use PHPUnit\Framework\TestCase;

use UnexpectedValueException;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;

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
        $this->expectException(AuthTokenParseException::class);
        new WebEidAuthToken("somestring");
    }
}
