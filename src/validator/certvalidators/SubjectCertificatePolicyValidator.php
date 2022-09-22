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

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateDisallowedPolicyException;
use web_eid\web_eid_authtoken_validation_php\util\Log;

final class SubjectCertificatePolicyValidator implements SubjectCertificateValidator
{
    private $disallowedSubjectCertificatePolicyIds = [];
    private Log $logger;

    public function __construct(array $disallowedSubjectCertificatePolicyIds)
    {
        $this->logger = Log::getLogger(self::class);
        $this->disallowedSubjectCertificatePolicyIds = $disallowedSubjectCertificatePolicyIds;
    }

    public function validate(X509 $subjectCertificate): void
    {
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

        $this->logger->debug("User certificate does not contain disallowed policies.");
    }
}
