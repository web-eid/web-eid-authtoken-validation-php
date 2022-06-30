<?php

namespace web_eid\web_eid_authtoken_validation_php\validator;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\util\Uri;
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