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