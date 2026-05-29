<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the challenge nonce has expired.
 */
class ChallengeNonceExpiredException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("Challenge nonce has expired");
    }
}
