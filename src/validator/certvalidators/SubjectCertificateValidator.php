<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use phpseclib3\File\X509;

/**
 * Validators perform the actual user certificate validation actions.
 * <p>
 * They are used by AuthTokenValidatorImpl and are not part of the public API.
 */
interface SubjectCertificateValidator
{
    public function validate(X509 $subjectCertificate): void;
}
