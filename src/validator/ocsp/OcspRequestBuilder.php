<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
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

use InvalidArgumentException;
use web_eid\web_eid_authtoken_validation_php\ocsp\OcspRequest;
use web_eid\web_eid_authtoken_validation_php\util\SecureRandom;

final class OcspRequestBuilder
{

    private $secureRandom;
    private bool $ocspNonceEnabled = true;
    private array $certificateId;

    public function __construct()
    {
        $this->secureRandom = function ($nonce_length): string {
            return SecureRandom::generate($nonce_length);
        };
    }

    public function withCertificateId(array $certificateId): OcspRequestBuilder
    {
        $this->certificateId = $certificateId;
        return $this;
    }

    public function enableOcspNonce(bool $ocspNonceEnabled): OcspRequestBuilder
    {
        $this->ocspNonceEnabled = $ocspNonceEnabled;
        return $this;
    }

    public function build(): OcspRequest
    {
        $ocspRequest = new OcspRequest();
        if (is_null($this->certificateId)) {
            throw new InvalidArgumentException("Certificate Id must not be null");
        }
        $ocspRequest->addCertificateId($this->certificateId);

        if ($this->ocspNonceEnabled) {
            $nonceBytes = call_user_func($this->secureRandom, 32);
            $ocspRequest->addNonceExtension($nonceBytes);
        }

        return $ocspRequest;
    }
}
