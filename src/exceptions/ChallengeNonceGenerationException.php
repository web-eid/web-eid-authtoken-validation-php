<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the challenge nonce generation fails
 */
class ChallengeNonceGenerationException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("Challenge nonce can not generated");
    }
}
