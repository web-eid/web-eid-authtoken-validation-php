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

use web_eid\web_eid_authtoken_validation_php\util\Uri;
use OpenSSLCertificate;

class AuthTokenValidatorBuilder
{
    private AuthTokenValidationConfiguration $configuration;

    public function __construct()
    {
        $this->configuration = new AuthTokenValidationConfiguration();
    }
    
    /**
     * Sets the expected site origin, i.e. the domain that the application is running on.
     * <p>
     * Origin is a mandatory configuration parameter.
     *
     * @param origin origin URL as defined in <a href="https://developer.mozilla.org/en-US/docs/Web/API/Location/origin">MDN</a>,
     *               in the form of {@code <scheme> "://" <hostname> [ ":" <port> ]}
     * @return the builder instance for method chaining
     */    
    public function withSiteOrigin(Uri $origin): AuthTokenValidatorBuilder 
    {
        $this->configuration->setSiteOrigin($origin);
        return $this;
    }

    /**
     * Adds the given certificates to the list of trusted intermediate Certificate Authorities
     * used during validation of subject and OCSP responder certificates.
     * In order for a user or OCSP responder certificate to be considered valid, the certificate
     * of the issuer of the certificate must be present in this list.
     * <p>
     * At least one trusted intermediate Certificate Authority must be provided as a mandatory configuration parameter.
     *
     * @param OpenSSLCertificate $certificates trusted intermediate Certificate Authority certificates
     * @return the builder instance for method chaining
     */    
    public function withTrustedCertificateAuthorities(OpenSSLCertificate ...$certificates): AuthTokenValidatorBuilder 
    {
        array_push($this->configuration->getTrustedCACertificates(), ...$certificates);
        return $this;
    }

    /**
     * Adds the given policies to the list of disallowed user certificate policies.
     * In order for the user certificate to be considered valid, it must not contain any policies
     * present in this list.
     *
     * @param string $policies disallowed user certificate policies as string array
     * @return the builder instance for method chaining
     */    
    public function withDisallowedCertificatePolicies(string ...$policies): AuthTokenValidatorBuilder 
    {
        array_push($this->configuration->getDisallowedSubjectCertificatePolicies(), ...$policies);
        return $this;
    }

    /**
     * Turns off user certificate revocation check with OCSP.
     * <p>
     * <b>Turning off user certificate revocation check with OCSP is dangerous and should be
     * used only in exceptional circumstances.</b>
     * By default, the revocation check is turned on.
     *
     * @return the builder instance for method chaining.
     */    
    public function withoutUserCertificateRevocationCheckWithOcsp(): AuthTokenValidatorBuilder
    {
        $this->configuration->setUserCertificateRevocationCheckWithOcspDisabled();
        return $this;
    }

    /**
     * Sets both the connection and response timeout of user certificate revocation check OCSP requests.
     * <p>
     * This is an optional configuration parameter, the default is 5 seconds.
     *
     * @param int $ocspRequestTimeout the duration of OCSP request connection and response timeout
     * @return the builder instance for method chaining.
     */    
    public function withOcspRequestTimeout(int $ocspRequestTimeout): AuthTokenValidatorBuilder
    {
        $this->configuration->setOcspRequestTimeout($ocspRequestTimeout);
        return $this;
    }

    /**
     * Adds the given URLs to the list of OCSP URLs for which the nonce protocol extension will be disabled.
     * The OCSP URL is extracted from the user certificate and some OCSP services don't support the nonce extension.
     *
     * @param URI $urls OCSP URLs for which the nonce protocol extension will be disabled
     * @return the builder instance for method chaining
     */    
    public function withNonceDisabledOcspUrls(URI ...$uris): AuthTokenValidatorBuilder
    {
        array_push($this->configuration->getNonceDisabledOcspUrls(), ...$uris);
        return $this;
    }

    // Implement
    public function withDesignatedOcspServiceConfiguration(): AuthTokenValidatorBuilder
    {
        return $this;
    }

    public function build(): AuthTokenValidator
    {
        $this->configuration->validate();
        return new AuthTokenValidatorImpl($this->configuration);
    }

}