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

namespace web_eid\web_eid_authtoken_validation_php\validator;

use GuzzleHttp\Psr7\Exception\MalformedUriException;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\testutil\AuthTokenValidators;
use web_eid\web_eid_authtoken_validation_php\testutil\Logger;

class AuthTokenValidatorBuilderTest extends TestCase
{

    private static AuthTokenValidatorBuilder $builder;

    protected function setUp(): void
    {
        self::$builder = new AuthTokenValidatorBuilder(new Logger());
    }

    public function testOriginMissing(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Origin URI must not be null");
        self::$builder->build();
    }

    public function testRootCertificateAuthorityMissing(): void
    {
        $builderWithMissingRootCa = (self::$builder)->withSiteOrigin(new Uri("https://ria.ee"));
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("At least one trusted certificate authority must be provided");
        $builderWithMissingRootCa->build();
    }

    public function testValidatorOriginNotUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Provided URI is not a valid URL");
        AuthTokenValidators::getAuthTokenValidator("not-url");
    }

    public function testValidatorOriginExcessiveElements(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Origin URI must only contain the HTTPS scheme, host and optional port component");
        AuthTokenValidators::getAuthTokenValidator("https://ria.ee/excessive-element");
    }

    public function testValidatorOriginNotHttps(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Origin URI must only contain the HTTPS scheme, host and optional port component");
        AuthTokenValidators::getAuthTokenValidator("http://ria.ee");
    }

    public function testValidatorOriginNotValidUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Origin URI must only contain the HTTPS scheme, host and optional port component");
        AuthTokenValidators::getAuthTokenValidator("ria://ria.ee");
    }

    public function testValidatorOriginNotValidSyntax(): void
    {
        $this->expectException(MalformedUriException::class);
        $this->expectExceptionMessage("Unable to parse URI: https:///ria.ee");
        AuthTokenValidators::getAuthTokenValidator("https:///ria.ee");
    }
}
