<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\challenge;

/**
 * Generates challenge nonces, cryptographically strong random bytestrings that must be used only once.
 */
interface ChallengeNonceGenerator
{
    /** 
     * @var int Integer indicating the length of bytes for challenge nonce
     */
    public const NONCE_LENGTH = 32;

    /**
     * Generates a cryptographic nonce, a large random number that can be used only once,
     * and stores it in a ChallengeNonceStore.
     *
     * @return ChallengeNonceStore that contains the Base64-encoded nonce and its expiry time
     */
    public function generateAndStoreNonce(): ChallengeNonce;
}
