<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\challenge;

use web_eid\web_eid_authtoken_validation_php\util\DateAndTime;

final class ChallengeNonceGeneratorImpl implements ChallengeNonceGenerator
{
    private ChallengeNonceStore $challengeNonceStore;
    private $secureRandom;
    private int $ttl;

    public function __construct(ChallengeNonceStore $challengeNonceStore, callable $secureRandom, int $ttl)
    {
        $this->challengeNonceStore = $challengeNonceStore;
        $this->secureRandom = $secureRandom;
        $this->ttl = $ttl;
    }

    public function generateAndStoreNonce(): ChallengeNonce
    {
        $nonceString = call_user_func($this->secureRandom, self::NONCE_LENGTH);
        $expirationTime = DateAndTime::utcNow()->modify("+{$this->ttl} seconds");
        $base64Nonce = base64_encode($nonceString);
        $challengeNonce = new ChallengeNonce($base64Nonce, $expirationTime);
        $this->challengeNonceStore->put($challengeNonce);
        return $challengeNonce;
    }
}
