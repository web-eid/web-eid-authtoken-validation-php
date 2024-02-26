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

namespace web_eid\web_eid_authtoken_validation_php\validator;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Uri;
use InvalidArgumentException;

class AuthTokenValidationConfigurationTest extends TestCase
{

    public function testWhenOriginUrlIsHttp(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Origin URI must only contain the HTTPS scheme, host and optional port component");
        $configuration = new AuthTokenValidationConfiguration();
        $configuration->setSiteOrigin(new Uri('http://example.com:81'));
        $configuration->validate();
    }

    public function testWhenNotAbsoluteUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Provided URI is not a valid URL");
        $configuration = new AuthTokenValidationConfiguration();
        $configuration->setSiteOrigin(new Uri('index.html'));
        $configuration->validate();
    }

    public function testWhenNoSiteOrigin(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Origin URI must not be null");
        $configuration = new AuthTokenValidationConfiguration();
        $configuration->validate();
    }

    public function testWhenNoTrustedCertificates(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("At least one trusted certificate authority must be provided");
        $configuration = new AuthTokenValidationConfiguration();
        $configuration->setSiteOrigin(new Uri('https://example.com:81'));
        $configuration->validate();
    }

    public function testWhenZeroOcspRequestTimeout(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("OCSP request timeout must be greater than zero");
        $configuration = new AuthTokenValidationConfiguration();
        $configuration->setSiteOrigin(new Uri('https://example.com:81'));
        $configuration->setOcspRequestTimeout(0);
        array_push($configuration->getTrustedCACertificates(), "1");
        $configuration->validate();
    }
}
