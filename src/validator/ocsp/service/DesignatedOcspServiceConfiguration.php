<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp\service;

use phpseclib3\File\X509;
use GuzzleHttp\Psr7\Uri;
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
        foreach ($supportedCertificateIssuers as $issuer) {
            $supportedIssuers[] = $issuer->getSubjectDN(X509::DN_STRING);
        }
        return $supportedIssuers;
    }
}
