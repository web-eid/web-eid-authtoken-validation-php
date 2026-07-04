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

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\certificate\IntermediateRevocationChecker;
use Psr\Log\LoggerInterface;

final class SubjectCertificateTrustedValidator implements
    SubjectCertificateValidator
{
    private TrustedCertificates $trustedCACertificates;
    private X509 $subjectCertificateIssuerCertificate;
    /** @var X509[] */
    private array $additionalIntermediateCertificates;
    private ?IntermediateRevocationChecker $intermediateRevocationChecker;
    private $logger;

    /**
     * @param X509[] $additionalIntermediateCertificates token-supplied untrusted intermediate CA
     *        certificates, used only as candidates during certification path building
     */
    public function __construct(
        TrustedCertificates $trustedCACertificates,
        ?LoggerInterface $logger = null,
        array $additionalIntermediateCertificates = [],
        ?IntermediateRevocationChecker $intermediateRevocationChecker = null,
    ) {
        $this->logger = $logger;
        $this->trustedCACertificates = $trustedCACertificates;
        $this->additionalIntermediateCertificates = $additionalIntermediateCertificates;
        $this->intermediateRevocationChecker = $intermediateRevocationChecker;
    }

    public function validate(X509 $subjectCertificate): void
    {
        // Intermediate CA certificates require revocation checks here because they are not
        // checked elsewhere. Subject certificate revocation is handled separately by
        // SubjectCertificateNotRevokedValidator.
        $this->subjectCertificateIssuerCertificate = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $subjectCertificate,
            $this->trustedCACertificates,
            "User",
            $this->additionalIntermediateCertificates,
            $this->intermediateRevocationChecker,
        );

        $this->logger?->debug(
            "Subject certificate is valid and signed by a trusted CA",
        );
    }

    /**
     * Returns the certificate that directly issued the subject certificate;
     * the trust anchor when the anchor is the direct issuer.
     */
    public function getSubjectCertificateIssuerCertificate(): X509
    {
        return $this->subjectCertificateIssuerCertificate;
    }
}
