<?php

/*
 * Copyright (c) 2025-2025 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\validator\versionvalidators;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;

class AuthTokenVersionValidatorFactoryTest extends TestCase
{
    public function testWhenValidatorSupportsFormat_thenSupportsReturnsTrue(): void
    {
        $v11 = $this->createMock(AuthTokenVersionValidator::class);
        $v11->method('supports')->with('web-eid:1.1')->willReturn(true);

        $factory = new AuthTokenVersionValidatorFactory([$v11]);

        $this->assertTrue($factory->supports('web-eid:1.1'));
    }

    public function testWhenValidatorDoesNotSupportFormat_thenSupportsReturnsFalse(): void
    {
        $v11 = $this->createMock(AuthTokenVersionValidator::class);
        $v11->method('supports')->willReturn(false);

        $factory = new AuthTokenVersionValidatorFactory([$v11]);

        $this->assertFalse($factory->supports('web-eid:2'));
    }

    /**
     * @dataProvider unsupportedFormats
     */
    public function testWhenUnsupportedFormat_thenGetValidatorForThrows(string $format): void
    {
        $factory = new AuthTokenVersionValidatorFactory([]);

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Token format version '{$format}' is currently not supported");

        $factory->getValidatorFor($format);
    }

    public static function unsupportedFormats(): array
    {
        return [
            ['web-eid:0.9'],
            ['web-eid:2'],
            ['foo'],
            ['1'],
            ['web-eid'],
        ];
    }

    public function testWhenFormatIsNullThenGetValidatorForThrowsParseException(): void
    {
        $factory = new AuthTokenVersionValidatorFactory([]);

        $this->expectException(AuthTokenParseException::class);
        $this->expectExceptionMessage("Token format version 'null' is currently not supported");

        $factory->getValidatorFor(null);
    }

    /**
     * @throws AuthTokenParseException
     */
    public function testWhenMultipleValidatorsAndFirstIsV11_thenGetValidatorForReturnsV11(): void
    {
        $v11 = $this->createMock(AuthTokenVersionValidator::class);
        $v11->method('supports')->with('web-eid:1.1')->willReturn(true);

        $v1 = $this->createMock(AuthTokenVersionValidator::class);
        $v1->method('supports')->with('web-eid:1.1')->willReturn(false);

        $factory = new AuthTokenVersionValidatorFactory([$v11, $v1]);

        $chosen = $factory->getValidatorFor('web-eid:1.1');

        $this->assertSame($v11, $chosen);
    }

    /**
     * @throws AuthTokenParseException
     */
    public function testWhenFormatIsBaseV1_thenGetValidatorForReturnsV1(): void
    {
        $v11 = $this->createMock(AuthTokenVersionValidator::class);
        $v11->method('supports')->willReturn(false);

        $v1 = $this->createMock(AuthTokenVersionValidator::class);
        $v1->method('supports')->with('web-eid:1')->willReturn(true);

        $factory = new AuthTokenVersionValidatorFactory([$v11, $v1]);

        $chosen = $factory->getValidatorFor('web-eid:1');

        $this->assertSame($v1, $chosen);
    }
}
