<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the user certificate purpose is not client authentication.
 */
class UserCertificateWrongPurposeException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("User certificate is not be used for authentication");
    }
}
