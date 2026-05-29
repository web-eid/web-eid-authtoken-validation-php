<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when user certificate parsing fails.
 */
class UserCertificateParseException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("Error parsing certificate");
    }
}
