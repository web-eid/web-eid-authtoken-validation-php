<?php

/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceNotFoundException;
use web_eid\web_eid_authtoken_validation_php\exceptions\SessionNotExistException;

class ChallengeNonceGeneratorTest extends TestCase
{
    private ChallengeNonceStore $challengeNonceStore;

    protected function setUp(): void
    {
        $session = array();
        $this->challengeNonceStore = new ChallengeNonceStore($session);
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
        $this->expectException(SessionNotExistException::class);
        new ChallengeNonceStore();
    }

}