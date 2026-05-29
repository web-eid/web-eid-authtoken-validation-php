<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\challenge;

use DateTime;

class ChallengeNonce
{

    /**
     * @var string Base64 encoded nonce
     */
    private string $base64EncodedNonce;

    /**
     * @var DateTime Nonce expiration time
     */
    private DateTime $expirationTime;

    public function __construct(string $base64EncodedNonce, DateTime $expirationTime)
    {
        $this->base64EncodedNonce = $base64EncodedNonce;
        $this->expirationTime = $expirationTime;
    }

    /**
     * Get base64 encoded nounce
     * 
     * @return string
     */
    public function getBase64EncodedNonce(): string
    {
        return $this->base64EncodedNonce;
    }

    /**
     * Get nounce expiration time
     * 
     * @return DateTime
     */
    public function getExpirationTime(): DateTime
    {
        return $this->expirationTime;
    }
}
