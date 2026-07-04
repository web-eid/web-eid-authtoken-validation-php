<?php

/*
 * Copyright (c) 2022-2026 Estonian Information System Authority
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
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;
use web_eid\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
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
    private X509 $certificateIssuerCertificate;
    /** @var X509[] */
    private array $additionalIntermediateCertificates;
    private bool $supportsNonce;

    /**
     * @param X509 $certificate the subject certificate whose revocation status is checked
     * @param X509 $certificateIssuerCertificate the certificate that directly issued the subject certificate
     * @param X509[] $additionalIntermediateCertificates token-supplied untrusted intermediate CA
     *        certificates, offered as candidates when building the responder certificate chain
     */
    public function __construct(
        AiaOcspServiceConfiguration $configuration,
        X509 $certificate,
        X509 $certificateIssuerCertificate,
        array $additionalIntermediateCertificates = [],
    ) {
        if (is_null($configuration)) {
            throw new InvalidArgumentException("Configuration cannot be null");
        }

        $this->url = self::getOcspAiaUrlFromCertificate($certificate);
        $this->trustedCACertificates = $configuration->getTrustedCACertificates();
        $this->certificateIssuerCertificate = $certificateIssuerCertificate;
        $this->additionalIntermediateCertificates = $additionalIntermediateCertificates;

        $this->supportsNonce = !in_array(
            $this->url->jsonSerialize(),
            $configuration->getNonceDisabledOcspUrls()->getUrlsArray()
        );
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
        // Certification path validation includes the date-validity check of the responder
        // certificate. Token-supplied intermediates are offered as path-building candidates.
        // Responder certificates are deliberately not revocation-checked (RFC 6960 4.2.2.2.1
        // id-pkix-ocsp-nocheck convention; querying an OCSP service about its own signer
        // certificate would be circular).
        $responderIssuerCertificate = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $cert,
            $this->trustedCACertificates,
            "AIA OCSP responder",
            $this->additionalIntermediateCertificates,
            null,
            $now,
        );

        // RFC 6960 section 4.2.2.2: the response must be signed by the CA that issued the
        // subject certificate or by a responder directly delegated by it. CA identity is
        // compared by subject and public key so that equivalent cross-certificates for the
        // same CA are accepted.
        if (self::representsSameCA($cert, $this->certificateIssuerCertificate)) {
            // The response is signed by the issuing CA itself; the OCSP-signing extended key
            // usage is required only for delegated responder certificates.
            return;
        }

        OcspResponseValidator::validateHasSigningExtension($cert);

        if (!self::representsSameCA($responderIssuerCertificate, $this->certificateIssuerCertificate)) {
            throw new CertificateNotTrustedException(
                $cert,
                new OCSPCertificateException("OCSP responder is not authorized by the subject certificate issuer"),
            );
        }
    }

    private static function representsSameCA(X509 $first, X509 $second): bool
    {
        return $first->getSubjectDN(X509::DN_STRING) === $second->getSubjectDN(X509::DN_STRING)
            && $first->getPublicKey()->toString('PKCS8') === $second->getPublicKey()->toString('PKCS8');
    }

    private static function getOcspAiaUrlFromCertificate(X509 $certificate): Uri
    {
        try {
            $uri = OcspUrl::getOcspUri($certificate);
        } catch (Exception $e) {
            throw new UserCertificateOCSPCheckFailedException(
                "Getting the AIA OCSP responder field from the certificate failed"
            );
        }

        if (is_null($uri)) {
            throw new UserCertificateOCSPCheckFailedException(
                "Getting the AIA OCSP responder field from the certificate failed"
            );
        }

        return $uri;
    }
}
