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

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use lyquidity\OCSP\CertificateInfo;
use lyquidity\OCSP\Ocsp;
use lyquidity\OCSP\Request;

final class OcspRequestBuilder
{

    private $secureRandom;
    private bool $ocspNonceEnabled = true;
    private $certificateId;

    public function __construct()
    {
        $this->secureRandom = function($nonce_length): string {
            return $this->generateSecureRandom($nonce_length);
        };
    }

    public function withCertificateId(Request $certInfo): OcspRequestBuilder
    {
        $this->certificateId = $certInfo;
        return $this;
    }

    public function enableOcspNonce(bool $ocspNonceEnabled): OcspRequestBuilder
    {
        $this->ocspNonceEnabled = $ocspNonceEnabled;
        return $this;
    }

    public function build()
    {
        $ocsp = new Ocsp();
        return $ocsp->buildOcspRequestBodySingle($this->certificateId);
    }

    private function generateSecureRandom(int $nounce_length): string {
        // Try random_bytes function as default for generating random bytes 
        if (function_exists('random_bytes')) {
            return random_bytes($nounce_length);
        }
        // Try openssl_random_pseudo_bytes function as second option for generating random bytes 
        if (function_exists('openssl_random_pseudo_bytes')) {
            return openssl_random_pseudo_bytes($nounce_length);
        }
    }


}