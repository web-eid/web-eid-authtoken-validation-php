<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use Psr\Log\LoggerInterface;
use web_eid\web_eid_authtoken_validation_php\util\DefaultClock;

final class SubjectCertificateTrustedValidator implements SubjectCertificateValidator
{
    private TrustedCertificates $trustedCACertificates;
    private X509 $subjectCertificateIssuerCertificate;
    private $logger;

    public function __construct(TrustedCertificates $trustedCACertificates, ?LoggerInterface $logger = null)
    {
        $this->logger = $logger;
        $this->trustedCACertificates = $trustedCACertificates;
    }

    public function validate(X509 $subjectCertificate): void
    {
        $this->subjectCertificateIssuerCertificate = CertificateValidator::validateIsValidAndSignedByTrustedCA(
            $subjectCertificate,
            $this->trustedCACertificates
        );

        $this->logger?->debug("Subject certificate is valid and signed by a trusted CA");
    }

    public function getSubjectCertificateIssuerCertificate(): X509
    {
        return $this->subjectCertificateIssuerCertificate;
    }
}
