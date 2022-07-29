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

use DateTime;
use web_eid\web_eid_authtoken_validation_php\util\Uri;
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

    public function validateResponderCertificate(X509 $cert, DateTime $producedAt): void
    {
        // Certificate pinning is implemented simply by comparing the certificates or their public keys,
        // see https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning.
        if ($this->configuration->getResponderCertificate()->getCurrentCert() != $cert->getCurrentCert()) {
            throw new OCSPCertificateException("Responder certificate from the OCSP response is not equal to the configured designated OCSP responder certificate");
        }        
        CertificateValidator::certificateIsValidOnDate($cert, $producedAt, "Designated OCSP responder");
    }

}