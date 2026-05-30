<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\util;

use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceGenerationException;

class SecureRandom
{

    public static function generate($nonce_length)
    {
        // Try random_bytes function as default for generating random bytes 
        if (function_exists("random_bytes")) {
            return random_bytes($nonce_length);
        }
        // Try openssl_random_pseudo_bytes function as second option for generating random bytes 
        if (function_exists("openssl_random_pseudo_bytes")) {
            return openssl_random_pseudo_bytes($nonce_length);
        }
        throw new ChallengeNonceGenerationException();
    }
}
