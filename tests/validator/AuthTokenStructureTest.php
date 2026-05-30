<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT


namespace web_eid\web_eid_authtoken_validation_php\validator;

use web_eid\web_eid_authtoken_validation_php\testutil\AbstractTestWithValidator;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;

class AuthTokenStructureTest extends AbstractTestWithValidator
{

    public function testWhenNullStrTokenThenParsingFails(): void
    {
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Auth token is null or too short");
        $this->validator->parse("null");
    }

    public function testWhenTokenTooShortThenParsingFails(): void
    {
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Auth token is null or too short");
        $this->validator->parse(str_repeat("1", 99));
    }

    public function testWhenTokenTooLongThenParsingFails(): void
    {
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Auth token is too long");
        $this->validator->parse(str_repeat("1", 10001));
    }

    public function testWhenUnknownTokenVersionThenParsingFails(): void
    {
        $token = $this->replaceTokenField(self::VALID_AUTH_TOKEN, "format", "invalid");
        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Only token format version 'web-eid:1' is currently supported");
        $this->validator->validate($token, "");
    }
}
