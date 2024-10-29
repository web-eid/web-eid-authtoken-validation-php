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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp\service;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspUrl;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use DateTime;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;
use Exception;
use InvalidArgumentException;

/**
 * An OCSP service that uses the responders from the Certificates' Authority Information Access (AIA) extension.
 */
class AiaOcspService implements OcspService
{

    private Uri $url;
    private TrustedCertificates $trustedCACertificates;
    private bool $supportsNonce;

    public function __construct(AiaOcspServiceConfiguration $configuration, X509 $certificate)
    {
        if (is_null($configuration)) {
            throw new InvalidArgumentException("Configuration cannot be null");
        }
        $this->url = self::getOcspAiaUrlFromCertificate($certificate);
        $this->trustedCACertificates = $configuration->getTrustedCACertificates();
        $this->supportsNonce = !in_array($this->url->jsonSerialize(), $configuration->getNonceDisabledOcspUrls()->getUrlsArray());
    }

    public function doesSupportNonce(): bool
    {
        return $this->supportsNonce;
    }

    public function getAccessLocation(): Uri
    {
        return $this->url;
    }

    public function validateResponderCertificate(X509 $cert, DateTime $now): void
    {
        CertificateValidator::certificateIsValidOnDate($cert, $now, "AIA OCSP responder");
        // Trusted certificates' validity has been already verified in validateCertificateExpiry().
        OcspResponseValidator::validateHasSigningExtension($cert);
        CertificateValidator::validateIsValidAndSignedByTrustedCA($cert, $this->trustedCACertificates);
    }

    private static function getOcspAiaUrlFromCertificate(X509 $certificate): Uri
    {
        try {
            $uri = OcspUrl::getOcspUri($certificate);
        } catch (Exception $e) {
            throw new UserCertificateOCSPCheckFailedException("Getting the AIA OCSP responder field from the certificate failed");
        }

        if (is_null($uri)) {
            throw new UserCertificateOCSPCheckFailedException("Getting the AIA OCSP responder field from the certificate failed");
        }
        return $uri;
    }
}
