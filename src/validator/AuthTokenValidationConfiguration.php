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

use web_eid\web_eid_authtoken_validation_php\util\SubjectCertificatePolicies;
use web_eid\web_eid_authtoken_validation_php\util\Uri;
use web_eid\web_eid_authtoken_validation_php\util\DateAndTime;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspUrl;

use InvalidArgumentException;

final class AuthTokenValidationConfiguration
{
    private ?Uri $siteOrigin = null;
    private array $trustedCACertificates = [];
    private bool $isUserCertificateRevocationCheckWithOcspEnabled = false;
    private int $ocspRequestTimeout = 5;
    private array $disallowedSubjectCertificatePolicies = [];
    private array $nonceDisabledOcspUrls = [];

    public function __construct()
    {
        // Don't allow Estonian Mobile-ID policy by default.
        $this->disallowedSubjectCertificatePolicies = [
            SubjectCertificatePolicies::$ESTEID_SK_2015_MOBILE_ID_POLICY_V1,
            SubjectCertificatePolicies::$ESTEID_SK_2015_MOBILE_ID_POLICY_V2,
            SubjectCertificatePolicies::$ESTEID_SK_2015_MOBILE_ID_POLICY_V3,
            SubjectCertificatePolicies::$ESTEID_SK_2015_MOBILE_ID_POLICY
        ];

        // Disable OCSP nonce extension for EstEID 2015 cards by default.
        $this->nonceDisabledOcspUrls[] = OcspUrl::AIA_ESTEID_2015_URL;
    }

    public function setSiteOrigin(Uri $siteOrigin): void
    {
        $this->siteOrigin = $siteOrigin;
    }

    public function getSiteOrigin(): ?Uri 
    {
        return $this->siteOrigin;
    }

    public function &getTrustedCACertificates(): array
    {
        return $this->trustedCACertificates;
    }

    public function isUserCertificateRevocationCheckWithOcspEnabled(): bool
    {
        return $this->isUserCertificateRevocationCheckWithOcspEnabled;
    }
    
    public function setUserCertificateRevocationCheckWithOcspDisabled(): void
    {
        $this->isUserCertificateRevocationCheckWithOcspEnabled = false;
    }

    public function getOcspRequestTimeout(): int
    {
        return $this->ocspRequestTimeout;
    }

    public function setOcspRequestTimeout(int $ocspRequestTimeout): void
    {
        $this->ocspRequestTimeout = $ocspRequestTimeout;
    }

    public function getDisallowedSubjectCertificatePolicies(): array
    {
        return $this->disallowedSubjectCertificatePolicies;
    }

    public function &getNonceDisabledOcspUrls(): array
    {
        return $this->nonceDisabledOcspUrls;
    }    

    /**
     * Checks that the configuration parameters are valid.
     *
     * @throws IllegalArgumentException when any parameter is invalid
     */    
    public function validate(): void
    {
        if (is_null($this->siteOrigin)) {
            throw new InvalidArgumentException('Origin URI must not be null');    
        }

        self::validateIsOriginURL($this->siteOrigin);

        if (count($this->trustedCACertificates) == 0) {
            throw new InvalidArgumentException('At least one trusted certificate authority must be provided');    
        }

        DateAndTime::requirePositiveDuration($this->ocspRequestTimeout, "OCSP request timeout");
    }

    /**
     * Validates that the given URI is an origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
     * in the form of {@code <scheme> "://" <hostname> [ ":" <port> ]}.
     *
     * @param uri URI with origin URL
     * @throws IllegalArgumentException when the URI is not in the form of origin URL
     */    
    public function validateIsOriginURL(Uri $uri): void
    {
        // 1. Verify that the URI can be converted to absolute URL.
        if (!$uri->isAbsolute()) {
            throw new InvalidArgumentException('Provided URI is not a valid URL');
        }

        // 2. Verify that the URI contains only HTTPS scheme, host and optional port components.
        if (!$uri->verifyComponents([
                "scheme" => "https",
                "host" => $uri->getHost(),
                "port" => $uri->getPort(),
            ])
        ) {
            throw new InvalidArgumentException('Origin URI must only contain the HTTPS scheme, host and optional port component');
        }

    }

}