<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\exceptions;

/**
 * Thrown when the challenge nonce was not found in the nonce store.
 */

class ChallengeNonceNotFoundException extends AuthTokenException
{
    public function __construct()
    {
        parent::__construct("Challenge nonce was not found in the nonce store");
    }
}
