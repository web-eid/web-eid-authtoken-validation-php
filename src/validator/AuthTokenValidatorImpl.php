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

namespace web_eid\web_eid_authtoken_validation_php\validator;

use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use Throwable;

final class AuthTokenValidatorImpl implements AuthTokenValidator
{

    private const TOKEN_MIN_LENGTH = 100;
    private const TOKEN_MAX_LENGTH = 10000;

    public function __construct(AuthTokenValidationConfiguration $configuration)
    {
        // Copy the configuration object to make AuthTokenValidatorImpl immutable and thread-safe.
        $this->configuration = clone $configuration;

        // Create and cache trusted CA certificate JCA objects for SubjectCertificateTrustedValidator and AiaOcspService.
        $this->trustedCertificates = [];

    }

    private function validateTokenLength(string $authToken): void
    {
        if (is_null($authToken) || strlen($authToken) < self::TOKEN_MIN_LENGTH) {
            throw new AuthTokenParseException('Auth token is null or too short');
        }
        if (strlen($authToken) > self::TOKEN_MAX_LENGTH) {
            throw new AuthTokenParseException('Auth token is too long');
        }
    }

    private function parseToken(string $authToken): WebEidAuthToken
    {
        try {
            $token = new WebEidAuthToken($authToken);
            return $token;
        } catch (Throwable $e) {
            throw $e;
        }
    }

    public function parse(string $authToken): WebEidAuthToken
    {
        try {
            $this->validateTokenLength($authToken);
            return $this->parseToken($authToken);

        } catch (Throwable $e) {
            throw $e;
        }
    } 

    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce)
    {
        return;
    } 
}