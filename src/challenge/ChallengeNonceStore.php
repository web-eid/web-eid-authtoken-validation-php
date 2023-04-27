<?php

/*
 * Copyright (c) 2022-2023 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace web_eid\web_eid_authtoken_validation_php\challenge;

use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonce;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceNotFoundException;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\SessionDoesNotExistException;
use web_eid\web_eid_authtoken_validation_php\util\DateAndTime;
use DateTime;

/**
 * A store for storing generated challenge nonces and accessing their generation time.
 */
class ChallengeNonceStore
{
    private const CHALLENGE_NONCE_SESSION_KEY = "web-eid-challenge-nonce";

    public function __construct()
    {
        if (!isset($_SESSION)) {
            if (PHP_SAPI === "cli") {
                throw new SessionDoesNotExistException();
            }
            if (!$this->doesSessionExist()) {
                throw new SessionDoesNotExistException();
            }
        }
    }

    /**
     * Store challenge nonce object into session
     * 
     * @param ChallengeNonce $challengeNonce - challenge nonce object
     */
    public function put(ChallengeNonce $challengeNonce)
    {
        $_SESSION[self::CHALLENGE_NONCE_SESSION_KEY] = serialize($challengeNonce);
    }

    /**
     * Get challenge nonce from store and remove it from store
     * 
     * @return null|ChallengeNonce
     */
    public function getAndRemove(): ?ChallengeNonce
    {

        if (!isset($_SESSION[self::CHALLENGE_NONCE_SESSION_KEY])) {
            throw new ChallengeNonceNotFoundException();
        }

        // Unserialize challenge nonce from session
        $challengeNonce = unserialize($_SESSION[self::CHALLENGE_NONCE_SESSION_KEY], [
            "allowed_classes" => [
                ChallengeNonce::class,
                DateTime::class
            ]
        ]);

        if (!$challengeNonce) {
            throw new ChallengeNonceNotFoundException();
        }

        if (DateAndTime::utcNow() > $challengeNonce->getExpirationTime()) {
            throw new ChallengeNonceExpiredException();
        }

        // Remove challenge nonce from session
        unset($_SESSION[self::CHALLENGE_NONCE_SESSION_KEY]);

        return $challengeNonce;
    }

    /**
     * Returns boolean, is session available
     *
     * @return bool
     */
    private function doesSessionExist(): bool
    {
        return (session_status() !== PHP_SESSION_NONE);
    }
}
