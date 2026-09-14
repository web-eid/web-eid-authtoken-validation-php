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

final class AuthTokenVersionTest extends TestCase
{
    /**
     * @dataProvider supportsCases
     */
    public function testWhenFormatMatchesRequiredMajorAndAtLeastRequiredMinorThenSupportsReturnsExpected(
        ?string $format,
        int $requiredMajorVersion,
        int $requiredMinorVersion,
        bool $expected,
    ): void {
        $this->assertSame(
            $expected,
            AuthTokenVersion::supports($format, $requiredMajorVersion, $requiredMinorVersion)
        );
    }

    public static function supportsCases(): array
    {
        return [
            ['web-eid:1', 1, 0, true],
            ['web-eid:1.0', 1, 0, true],
            ['web-eid:1.1', 1, 0, true],
            ['web-eid:1.1', 1, 1, true],
            ['web-eid:1.999', 1, 1, true],
            ['web-eid:2.0', 2, 0, true],
            ['web-eid:2.3', 2, 1, true],
            ['web-eid:1.0', 1, 1, false],
            ['web-eid:1', 1, 1, false],
            ['web-eid:2', 1, 0, false],
            ['web-eid:1.5', 2, 0, false],
            ['web-eid:1.00', 1, 0, false],
            ['web-eid:1.000', 1, 0, false],
            ['web-eid:01', 1, 0, false],
            ['web-eid:1.', 1, 0, false],
            ['web-eid:1.1.0', 1, 0, false],
            ['web-eid:0.9', 1, 0, false],
            ['webauthn:1', 1, 0, false],
            [null, 1, 0, false],
            ['', 1, 0, false],
        ];
    }

    /**
     * @dataProvider supportsExactlyCases
     */
    public function testWhenFormatMatchesRequiredMajorAndExactMinorThenSupportsExactlyReturnsExpected(
        ?string $format,
        int $requiredMajorVersion,
        int $requiredMinorVersion,
        bool $expected,
    ): void {
        $this->assertSame(
            $expected,
            AuthTokenVersion::supportsExactly($format, $requiredMajorVersion, $requiredMinorVersion)
        );
    }

    public static function supportsExactlyCases(): array
    {
        return [
            ['web-eid:1', 1, 0, true],
            ['web-eid:1.0', 1, 0, true],
            ['web-eid:1.1', 1, 1, true],
            ['web-eid:2.0', 2, 0, true],
            ['web-eid:1.1', 1, 0, false],
            ['web-eid:1.2', 1, 1, false],
            ['web-eid:1.0', 1, 1, false],
            ['web-eid:1', 2, 0, false],
            ['web-eid:1.00', 1, 0, false],
            ['web-eid:01', 1, 0, false],
            ['webauthn:1', 1, 0, false],
            [null, 1, 0, false],
            ['', 1, 0, false],
        ];
    }
}
