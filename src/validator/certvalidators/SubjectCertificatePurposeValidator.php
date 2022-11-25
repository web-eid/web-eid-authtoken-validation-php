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
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateMissingPurposeException;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateWrongPurposeException;
use Psr\Log\LoggerInterface;

final class SubjectCertificatePurposeValidator implements SubjectCertificateValidator
{

    // oid 1.3.6.1.5.5.7.3.2
    private const EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION = "id-kp-clientAuth";
    private $logger;

    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
    }

    /**
     * Validates that the purpose of the user certificate from the authentication token contains client authentication.
     *
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     * 
     * @param subjectCertificate user certificate to be validated
     * @throws UserCertificateMissingPurposeException
     */
    public function validate(X509 $subjectCertificate): void
    {
        $usages = $subjectCertificate->getExtension('id-ce-extKeyUsage');
        if (!$usages || empty($usages)) {
            throw new UserCertificateMissingPurposeException();
        }
        // Extended usages must contain TLS Web Client Authentication
        if (!in_array(self::EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION, $usages)) {
            throw new UserCertificateWrongPurposeException();
        }

        $this->logger?->debug("User certificate can be used for client authentication.");
    }
}
