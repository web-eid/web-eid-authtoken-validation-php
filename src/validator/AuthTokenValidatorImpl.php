<?php

/*
 * Copyright (c) 2022-2025 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\validator;

use phpseclib3\File\X509;
use Throwable;
use Psr\Log\LoggerInterface;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenException;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use web_eid\web_eid_authtoken_validation_php\validator\versionvalidators\AuthTokenVersionValidatorFactory;

final class AuthTokenValidatorImpl implements AuthTokenValidator
{
    private const TOKEN_MIN_LENGTH = 100;
    private const TOKEN_MAX_LENGTH = 10000;

    private AuthTokenVersionValidatorFactory $tokenValidatorFactory;
    private ?LoggerInterface $logger;

    public function __construct(
        AuthTokenValidationConfiguration $configuration,
        ?LoggerInterface $logger = null,
        ?OcspClient $ocspClient = null
    ) {
        $this->logger = $logger;

        $this->tokenValidatorFactory =
            AuthTokenVersionValidatorFactory::create(
                $configuration,
                $ocspClient,
                $logger
            );
    }

    /**
     * @throws AuthTokenParseException
     * @throws Throwable
     */
    public function parse(string $authToken): WebEidAuthToken
    {
        $this->logger?->info("Starting token parsing");

        try {
            $this->validateTokenLength($authToken);
            return new WebEidAuthToken($authToken);
        } catch (Throwable $e) {
            $this->logger?->warning("Token parsing was interrupted: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * @throws AuthTokenParseException
     * @throws Throwable
     * @throws AuthTokenException
     */
    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce): X509
    {
        $this->logger?->info("Starting token validation");

        try {
            $validator = $this->tokenValidatorFactory
                ->getValidatorFor($authToken->getFormat());

            return $validator->validate($authToken, $currentChallengeNonce);

        } catch (Throwable $e) {
            $this->logger?->warning("Token validation was interrupted: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * @throws AuthTokenParseException
     */
    private function validateTokenLength(string $authToken): void
    {
        if (strlen($authToken) < self::TOKEN_MIN_LENGTH) {
            throw new AuthTokenParseException("Auth token is null or too short");
        }
        if (strlen($authToken) > self::TOKEN_MAX_LENGTH) {
            throw new AuthTokenParseException("Auth token is too long");
        }
    }
}
