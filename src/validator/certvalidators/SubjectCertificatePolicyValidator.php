<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateDisallowedPolicyException;
use Psr\Log\LoggerInterface;

final class SubjectCertificatePolicyValidator implements SubjectCertificateValidator
{
    private $disallowedSubjectCertificatePolicyIds = [];
    private $logger;

    public function __construct(array $disallowedSubjectCertificatePolicyIds, ?LoggerInterface $logger = null)
    {
        $this->logger = $logger;
        $this->disallowedSubjectCertificatePolicyIds = $disallowedSubjectCertificatePolicyIds;
    }

    public function validate(X509 $subjectCertificate): void
    {
        $this->logger?->debug("Validating");

        // No need to validate
        if (count($this->disallowedSubjectCertificatePolicyIds) == 0) {
            return;
        }

        $policies = $subjectCertificate->getExtension('id-ce-certificatePolicies');
        // When there is no certificatePolicies or certificate parse failed
        if (!$policies) {
            return;
        }

        // Loop through disallowed policies array
        foreach ($policies as $policy) {
            if (in_array($policy['policyIdentifier'], $this->disallowedSubjectCertificatePolicyIds)) {
                throw new UserCertificateDisallowedPolicyException();
            }
        }

        $this->logger?->debug("User certificate does not contain disallowed policies.");
    }
}
