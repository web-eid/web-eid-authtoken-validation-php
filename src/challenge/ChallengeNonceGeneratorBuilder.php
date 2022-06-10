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

use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceGenerationException;

class ChallengeNonceGeneratorBuilder
{
    /**
     * @var int Challenge nounce length.
     */
    private const NOUNCE_LENGTH = 32;

    /**
     * @var int Challenge nounce max validity in minutes.
     */
    private const TTL = 5;

    /**
     * @var string Random bytes
     */
    private string $secureRandom;

    public function __construct()
    {
        $this->secureRandom = $this->generateSecureRandom();
    }    

    private function generateSecureRandom() {
        // Try random_bytes function as default for generating random bytes 
        if (function_exists('random_bytes')) {
            $this->secureRandom = random_bytes(self::NOUNCE_LENGTH);
            return;
        }
        // Try openssl_random_pseudo_bytes function as second option for generating random bytes 
        if (function_exists('openssl_random_pseudo_bytes')) {
            $this->secureRandom = openssl_random_pseudo_bytes(self::NOUNCE_LENGTH);
            return;
        }
        throw new ChallengeNonceGenerationException();

    }

}