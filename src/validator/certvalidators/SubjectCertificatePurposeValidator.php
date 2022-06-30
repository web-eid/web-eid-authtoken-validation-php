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

use web_eid\web_eid_authtoken_validation_php\util\X509;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateMissingPurposeException;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateWrongPurposeException;

final class SubjectCertificatePurposeValidator implements SubjectCertificateValidator
{

    private const EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION = "TLS Web Client Authentication";

    /**
     * Validates that the purpose of the user certificate from the authentication token contains client authentication.
     *
     * @param subjectCertificate user certificate to be validated
     * @throws UserCertificateMissingPurposeException
     */    
    public function validate(X509 $subjectCertificate): void
    {
        $usages = $subjectCertificate->getExtendedKeyUsage();
        if (!$usages) {
            throw new UserCertificateMissingPurposeException();
        }
        // Extended usages must contain TLS Web Client Authentication
        if (!in_array(self::EXTENDED_KEY_USAGE_CLIENT_AUTHENTICATION, $usages)) {
            throw new UserCertificateWrongPurposeException();
        }        
    }
}