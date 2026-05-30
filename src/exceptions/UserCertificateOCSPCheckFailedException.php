<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

use Throwable;

/**
 * Thrown when user certificate revocation check with OCSP fails.
 */
class UserCertificateOCSPCheckFailedException extends AuthTokenException
{
    public function __construct(string $message, ?Throwable $cause = null)
    {
        parent::__construct("User certificate revocation check has failed: " . $message, $cause);
    }
}
