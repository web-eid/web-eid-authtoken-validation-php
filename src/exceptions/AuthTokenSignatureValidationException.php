<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

class AuthTokenSignatureValidationException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("Token signature validation has failed. Check that the origin and nonce are correct.");
    }
}
