<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the user certificate purpose field is missing or empty.
 */
class UserCertificateMissingPurposeException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("User certificate purpose is missing");
    }
}
