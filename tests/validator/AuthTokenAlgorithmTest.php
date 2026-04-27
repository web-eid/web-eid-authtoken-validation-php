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

namespace web_eid\web_eid_authtoken_validation_php\validator;

use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\testutil\AbstractTestWithValidator;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;

class AuthTokenAlgorithmTest extends AbstractTestWithValidator
{
    public function testWhenAlgorithmNoneThenValidationFails(): void
    {
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, "algorithm", "NONE");

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Unsupported signature algorithm");
        $this->validator->validate($authToken, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenAlgorithmEmptyThenParsingFails(): void
    {
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, 'algorithm', '');

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'algorithm' is null or empty");
        $this->validator->validate($authToken, self::VALID_CHALLENGE_NONCE);
    }

    public function testWhenAlgorithmInvalidThenParsingFails(): void
    {
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, "algorithm", "\\u0000\\t\\ninvalid");

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Unsupported signature algorithm");
        $this->validator->validate($authToken, self::VALID_CHALLENGE_NONCE);
    }

    /**
     * @throws AuthTokenParseException
     */
    public function testWhenV11TokenMissingSupportedAlgorithmsThenValidationFails(): void
    {
        $tokenFields = json_decode(self::VALID_V11_AUTH_TOKEN, true);
        unset($tokenFields['unverifiedSigningCertificates'][0]['supportedSignatureAlgorithms']);

        $tokenJson = json_encode($tokenFields, JSON_UNESCAPED_SLASHES);
        $authToken = new WebEidAuthToken($tokenJson);

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'supportedSignatureAlgorithms' field is missing");

        $this->validator->validate($authToken, self::VALID_CHALLENGE_NONCE);
    }

    /**
     * @throws AuthTokenParseException
     */
    public function testWhenV11TokenHasInvalidCryptoAlgorithmThenValidationFails(): void
    {
        $tokenJson = $this->replaceJsonSnippet(
            self::VALID_V11_AUTH_TOKEN,
            '"cryptoAlgorithm":"RSA"',
            '"cryptoAlgorithm":"INVALID"'
        );

        $authToken = new WebEidAuthToken($tokenJson);

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Unsupported signature algorithm");

        $this->validator->validate($authToken, self::VALID_CHALLENGE_NONCE);
    }

    /**
     * @throws AuthTokenParseException
     */
    public function testWhenV11TokenHasInvalidHashFunctionThenValidationFails(): void
    {
        $tokenJson = $this->replaceJsonSnippet(
            self::VALID_V11_AUTH_TOKEN,
            '"hashFunction":"SHA-256"',
            '"hashFunction":"NOT_A_HASH"'
        );

        $authToken = new WebEidAuthToken($tokenJson);

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Unsupported signature algorithm");

        $this->validator->validate($authToken, self::VALID_CHALLENGE_NONCE);
    }

    /**
     * @throws AuthTokenParseException
     */
    public function testWhenV11TokenHasInvalidPaddingSchemeThenValidationFails(): void
    {
        $tokenJson = $this->replaceJsonSnippet(
            self::VALID_V11_AUTH_TOKEN,
            '"paddingScheme":"PKCS1.5"',
            '"paddingScheme":"BAD_PADDING"'
        );

        $authToken = new WebEidAuthToken($tokenJson);

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Unsupported signature algorithm");

        $this->validator->validate($authToken, self::VALID_CHALLENGE_NONCE);
    }

    /**
     * @throws AuthTokenParseException
     */
    public function testWhenV11TokenHasEmptySupportedAlgorithmsThenValidationFails(): void
    {
        $tokenJson = $this->replaceJsonSnippet(
            self::VALID_V11_AUTH_TOKEN,
            '"supportedSignatureAlgorithms":[{"cryptoAlgorithm":"RSA","hashFunction":"SHA-256","paddingScheme":"PKCS1.5"}]',
            '"supportedSignatureAlgorithms":[]'
        );

        $authToken = new WebEidAuthToken($tokenJson);

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'supportedSignatureAlgorithms' field is missing");

        $this->validator->validate($authToken, self::VALID_CHALLENGE_NONCE);
    }
}
