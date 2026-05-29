<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when any of the configured disallowed policies is present in the user certificate.
 */
class UserCertificateDisallowedPolicyException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("Disallowed user certificate policy");
    }
}
