<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when PHP session is not started (session_start() is not executed)
 */
class SessionDoesNotExistException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("PHP session not started");
    }
}
