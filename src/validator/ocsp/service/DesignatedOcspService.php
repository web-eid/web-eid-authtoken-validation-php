<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp\service;

use DateTime;
use GuzzleHttp\Psr7\Uri;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;

/**
 * An OCSP service that uses a single designated OCSP responder.
 */
class DesignatedOcspService implements OcspService
{
    private DesignatedOcspServiceConfiguration $configuration;

    public function __construct(DesignatedOcspServiceConfiguration $configuration)
    {
        $this->configuration = $configuration;
    }

    public function doesSupportNonce(): bool
    {
        return $this->configuration->doesSupportNonce();
    }

    public function getAccessLocation(): Uri
    {
        return $this->configuration->getOcspServiceAccessLocation();
    }

    public function supportsIssuerOf(X509 $certificate): bool
    {
        return $this->configuration->supportsIssuerOf($certificate);
    }

    public function validateResponderCertificate(X509 $cert, DateTime $now): void
    {
        // Certificate pinning is implemented simply by comparing the certificates or their public keys,
        // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
        if ($this->configuration->getResponderCertificate()->getCurrentCert() != $cert->getCurrentCert()) {
            throw new OCSPCertificateException("Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");
        }
        CertificateValidator::certificateIsValidOnDate($cert, $now, "Designated OCSP responder");
    }
}
