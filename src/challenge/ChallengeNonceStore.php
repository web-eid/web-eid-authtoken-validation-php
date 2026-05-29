<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
