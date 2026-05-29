<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\challenge;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceNotFoundException;
use web_eid\web_eid_authtoken_validation_php\exceptions\SessionDoesNotExistException;

class ChallengeNonceGeneratorTest extends TestCase
{
    private ChallengeNonceStore $challengeNonceStore;

    protected function setUp(): void
    {
        // Set session for tests
        $_SESSION = [];
        $this->challengeNonceStore = new ChallengeNonceStore();
    }

    public function testValidateNonceGeneration(): void
    {
        $challengeNonceGenerator = (new ChallengeNonceGeneratorBuilder())->withChallengeNonceStore($this->challengeNonceStore)->withNonceTtl(1)->build();

        $nonce1 = $challengeNonceGenerator->generateAndStoreNonce();
        $nonce2 = $challengeNonceGenerator->generateAndStoreNonce();

        // Base64-encoded 32 bytes = 44 strlen
        $this->assertTrue(44 == strlen($nonce1->getBase64EncodedNonce()));
        $this->assertNotEquals($nonce1->getBase64EncodedNonce(), $nonce2->getBase64EncodedNonce());
    }

    public function testValidateUnexpiredNonce()
    {
        $this->expectNotToPerformAssertions();
        $challengeNonceGenerator = (new ChallengeNonceGeneratorBuilder())->withChallengeNonceStore($this->challengeNonceStore)->withNonceTtl(2)->build();
        $challengeNonceGenerator->generateAndStoreNonce();
        sleep(1);
        $this->challengeNonceStore->getAndRemove();
    }

    public function testValidateNonceExpiration()
    {
        $this->expectException(ChallengeNonceExpiredException::class);
        $challengeNonceGenerator = (new ChallengeNonceGeneratorBuilder())->withChallengeNonceStore($this->challengeNonceStore)->withNonceTtl(1)->build();
        $challengeNonceGenerator->generateAndStoreNonce();
        sleep(2);
        $this->challengeNonceStore->getAndRemove();
    }

    public function testValidateNonceNotFound()
    {
        $this->expectException(ChallengeNonceNotFoundException::class);
        $this->challengeNonceStore->getAndRemove();
    }

    public function testWhenSessionNotStartedThenStoreFails()
    {
        $this->expectException(SessionDoesNotExistException::class);
        unset($_SESSION);
        new ChallengeNonceStore();
    }

}
