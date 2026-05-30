<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator;

use web_eid\web_eid_authtoken_validation_php\testutil\AbstractTestWithValidator;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;

class AuthTokenAlgorithmTest extends AbstractTestWithValidator
{

    public function testWhenAlgorithmNoneThenValidationFails(): void
    {
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, "algorithm", "NONE");

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Unsupported signature algorithm");
        $this->validator->validate($authToken, self::VALID_AUTH_TOKEN);
    }

    public function testWhenAlgorithmEmptyThenParsingFails(): void
    {
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, 'algorithm', '');

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("'algorithm' is null or empty");
        $this->validator->validate($authToken, self::VALID_AUTH_TOKEN);
    }

    public function testWhenAlgorithmInvalidThenParsingFails(): void
    {
        $authToken = $this->replaceTokenField(self::VALID_AUTH_TOKEN, "algorithm", "\\u0000\\t\\ninvalid");

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Unsupported signature algorithm");
        $this->validator->validate($authToken, self::VALID_AUTH_TOKEN);
    }
}
