<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
