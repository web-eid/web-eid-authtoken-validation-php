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
