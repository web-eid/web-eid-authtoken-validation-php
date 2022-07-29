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
declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp\service;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\util\Uri;
use web_eid\web_eid_authtoken_validation_php\util\X509Collection;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;

class DesignatedOcspServiceConfiguration
{
    private Uri $ocspServiceAccessLocation;
    private X509 $responderCertificate;
    private bool $doesSupportNonce;
    private array $supportedIssuers;

    /**
     * Configuration of a designated OCSP service.
     *
     * @param Uri $ocspServiceAccessLocation - the URL where the service is located
     * @param X509 $responderCertificate - the service's OCSP responder certificate
     * @param X509Collection $supportedCertificateIssuers - the certificate issuers supported by the service
     * @param bool $doesSupportNonce - true if the service supports the OCSP protocol nonce extension
     * @throws OCSPCertificateException when an error occurs while extracting issuer names from certificates
     */    
    public function __construct(Uri $ocspServiceAccessLocation, X509 $responderCertificate, X509Collection $supportedCertificateIssuers, bool $doesSupportNonce)
    {

        $this->ocspServiceAccessLocation = $ocspServiceAccessLocation;
        $this->responderCertificate = $responderCertificate;
        $this->supportedIssuers = $this->getIssuerX500Names($supportedCertificateIssuers);
        $this->doesSupportNonce = $doesSupportNonce;

        OcspResponseValidator::validateHasSigningExtension($responderCertificate);
    }

    public function getOcspServiceAccessLocation(): Uri
    {
        return  $this->ocspServiceAccessLocation;
    }

    public function getResponderCertificate(): X509
    {
        return $this->responderCertificate;
    }

    public function doesSupportNonce(): bool
    {
        return $this->doesSupportNonce;
    }

    public function supportsIssuerOf(X509 $certificate): bool
    {
        return in_array($certificate->getIssuerDN(X509::DN_STRING), $this->supportedIssuers);
    }

    private function getIssuerX500Names(X509Collection $supportedCertificateIssuers): array
    {
        $supportedIssuers = [];
        foreach($supportedCertificateIssuers as $issuer) {
            $supportedIssuers[] = $issuer->getSubjectDN(X509::DN_STRING);
        }
        return $supportedIssuers;
    }

}