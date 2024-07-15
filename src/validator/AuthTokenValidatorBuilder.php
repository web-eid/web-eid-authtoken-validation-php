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

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator;

use GuzzleHttp\Psr7\Uri;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\util\X509Collection;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\DesignatedOcspServiceConfiguration;
use Psr\Log\LoggerInterface;

class AuthTokenValidatorBuilder
{
    private AuthTokenValidationConfiguration $configuration;
    private $logger;

    public function __construct(LoggerInterface $logger = null)
    {
        $this->configuration = new AuthTokenValidationConfiguration();
        $this->logger = $logger;
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
        $this->logger?->debug("Origin set to " . $this->configuration->getSiteOrigin()->jsonSerialize());
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
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     * 
     * @param X509 $certificates trusted intermediate Certificate Authority certificates
     * @return the builder instance for method chaining
     */
    public function withTrustedCertificateAuthorities(X509 ...$certificates): AuthTokenValidatorBuilder
    {
        array_push($this->configuration->getTrustedCACertificates(), ...$certificates);
        $this->logger?->debug("Trusted intermediate certificate authorities set to " . json_encode(X509Collection::getSubjectDNs(null, ...$this->configuration->getTrustedCACertificates())));
        return $this;
    }

    /**
     * Adds the given policies to the list of disallowed user certificate policies.
     * In order for the user certificate to be considered valid, it must not contain any policies
     * present in this list.
     * 
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     *
     * @param string $policies disallowed user certificate policies as string array
     * @return the builder instance for method chaining
     */
    public function withDisallowedCertificatePolicies(string ...$policies): AuthTokenValidatorBuilder
    {
        array_push($this->configuration->getDisallowedSubjectCertificatePolicies(), ...$policies);
        $this->logger?->debug("Disallowed subject certificate policies set to " . json_encode($this->configuration->getDisallowedSubjectCertificatePolicies()));
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
        $this->logger?->warning("User certificate revocation check with OCSP is disabled, you should turn off the revocation check only in exceptional circumstances");
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
        $this->logger?->debug("OCSP request timeout set to " . $ocspRequestTimeout);
        return $this;
    }
    
    /**
     * Sets the allowed time skew for OCSP response's thisUpdate and nextUpdate times.
     * This parameter is used to allow discrepancies between the system clock and the OCSP responder's clock,
     * which may occur due to clock drift, network delays or revocation updates that are not published in real time.
     * <p>
     * This is an optional configuration parameter, the default is 15 minutes.
     * The relatively long default is specifically chosen to account for one particular OCSP responder that used
     * CRLs for authoritative revocation info, these CRLs were updated every 15 minutes.
     * 
     * @param integer $allowedTimeSkew the allowed time skew
     * @return AuthTokenValidatorBuilder the builder instance for method chaining.
     */
    public function withAllowedOcspResponseTimeSkew(int $allowedTimeSkew) : AuthTokenValidatorBuilder
    {
        $this->configuration->setAllowedOcspResponseTimeSkew($allowedTimeSkew);
        $this->logger?->debug("Allowed OCSP response time skew set to " . $allowedTimeSkew);
        return $this;
    }

    /**
     * Sets the maximum age of the OCSP response's thisUpdate time before it is considered too old.
     * <p>
     * This is an optional configuration parameter, the default is 2 minutes.
     * 
     * @param integer $maxThisUpdateAge the maximum age of the OCSP response's thisUpdate time
     * @return AuthTokenValidatorBuilder the builder instance for method chaining.
     */
    public function withMaxOcspResponseThisUpdateAge(int $maxThisUpdateAge) : AuthTokenValidatorBuilder
    {
        $this->configuration->setMaxOcspResponseThisUpdateAge($maxThisUpdateAge);
        $this->logger?->debug("Maximum OCSP response thisUpdate age set to " . $maxThisUpdateAge);
        return $this;
    }

    /**
     * Adds the given URLs to the list of OCSP URLs for which the nonce protocol extension will be disabled.
     * The OCSP URL is extracted from the user certificate and some OCSP services don't support the nonce extension.
     *
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     * 
     * @param URI $urls OCSP URLs for which the nonce protocol extension will be disabled
     * @return the builder instance for method chaining
     */
    public function withNonceDisabledOcspUrls(URI ...$uris): AuthTokenValidatorBuilder
    {
        foreach ($uris as $uri) {
            $this->configuration->getNonceDisabledOcspUrls()->pushItem($uri);
        }
        $this->logger?->debug("OCSP URLs for which the nonce protocol extension is disabled set to " . implode(", ", $this->configuration->getNonceDisabledOcspUrls()->getUrlsArray()));

        return $this;
    }

    public function withDesignatedOcspServiceConfiguration(DesignatedOcspServiceConfiguration $serviceConfiguration): AuthTokenValidatorBuilder
    {
        $this->configuration->setDesignatedOcspServiceConfiguration($serviceConfiguration);
        $this->logger?->debug("Using designated OCSP service configuration");
        return $this;
    }

    public function build(): AuthTokenValidator
    {
        $this->configuration->validate();
        return new AuthTokenValidatorImpl($this->configuration, $this->logger);
    }
}
