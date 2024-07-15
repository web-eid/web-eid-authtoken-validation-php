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

namespace web_eid\web_eid_authtoken_validation_php\testutil;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateLoader;
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidatorBuilder;

final class AuthTokenValidators
{

    private const TOKEN_ORIGIN_URL = "https://ria.ee";
    private const EST_IDEMIA_POLICY = "1.3.6.1.4.1.51361.1.2.1";

    public static function getAuthTokenValidator(string $url = self::TOKEN_ORIGIN_URL, X509 ...$certificates): AuthTokenValidator
    {
        if (empty($certificates)) {
            $certificates = self::getCACertificates();
        }
        return (self::getAuthTokenValidatorBuilder($url, $certificates))
            ->withOcspRequestTimeout(1)
            ->withNonceDisabledOcspUrls(new Uri("http://example.org"))
            ->withoutUserCertificateRevocationCheckWithOcsp()
            ->build();
    }

    public static function getAuthTokenValidatorWithOcspCheck(): AuthTokenValidator
    {
        return (self::getAuthTokenValidatorBuilder(self::TOKEN_ORIGIN_URL, self::getCACertificates()))->build();
    }

    public static function getAuthTokenValidatorWithDesignatedOcspCheck()
    {
        return (self::getAuthTokenValidatorBuilder(self::TOKEN_ORIGIN_URL, self::getCACertificates()))->withDesignatedOcspServiceConfiguration(OcspServiceMaker::getDesignatedOcspServiceConfiguration())->build();
    }

    public static function getDefaultAuthTokenValidatorBuilder(): AuthTokenValidatorBuilder
    {
        return self::getAuthTokenValidatorBuilder(self::TOKEN_ORIGIN_URL, self::getCACertificates());
    }

    private static function getAuthTokenValidatorBuilder(string $uri, array $certificates): AuthTokenValidatorBuilder
    {
        return (new AuthTokenValidatorBuilder(new Logger()))
            ->withSiteOrigin(new Uri($uri))
            ->withTrustedCertificateAuthorities(...$certificates);
    }

    public static function getAuthTokenValidatorWithJuly2024ExpiredUnrelatedTrustedCA(): AuthTokenValidator
    {
        return self::getAuthTokenValidator(
            self::TOKEN_ORIGIN_URL,
            ...CertificateLoader::loadCertificatesFromResources(
                __DIR__ . "/../_resources/TEST_of_ESTEID2018.cer",
                __DIR__ . "/../_resources/TEST_of_SK_OCSP_RESPONDER_2020.cer"
            )
        );
    }

    public static function getAuthTokenValidatorWithDisallowedESTEIDPolicy(): AuthTokenValidator
    {
        return (self::getAuthTokenValidatorBuilder(self::TOKEN_ORIGIN_URL, self::getCACertificates()))
            ->withDisallowedCertificatePolicies(self::EST_IDEMIA_POLICY)
            ->withoutUserCertificateRevocationCheckWithOcsp()
            ->build();
    }

    public static function getAuthTokenValidatorWithWrongTrustedCertificate(): AuthTokenValidator
    {
        return self::getAuthTokenValidator(
            self::TOKEN_ORIGIN_URL,
            ...CertificateLoader::loadCertificatesFromResources(__DIR__ . "/../_resources/ESTEID2018.cer")
        );
    }

    private static function getCACertificates(): array
    {
        return CertificateLoader::loadCertificatesFromResources(__DIR__ . "/../_resources/TEST_of_ESTEID2018.cer");
    }
}
