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

namespace web_eid\web_eid_authtoken_validation_php\util;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AsnUtilTest extends TestCase
{
    public function testTranscodeSignatureToDer(): void
    {
        $signature = "7V8AcyP23QWuVZAOSJuZ2cLLn3l41VgTmQ4q9GTjV8ENkFKAXtwVk8cTvfVODl3ZU4xEA9CvF6xJ8ysBdAew8Q";
        $decodedSignature = base64_decode($signature);
        $result = AsnUtil::transcodeSignatureToDER($decodedSignature);
        $valueArr = [];
        for ($i = 0; $i < strlen($result); $i++) {
            $valueArr[$i] = ord($result[$i]);
        }
        // First byte value
        $this->assertEquals($valueArr[0], 48);
        // Length
        $this->assertEquals($valueArr[1], count($valueArr) - 2);
        // Third byte value must be 2
        $this->assertEquals($valueArr[2], 2);
        // Next byte value 2 positon
        $separator = $valueArr[$valueArr[3] + 4];
        $this->assertEquals($separator, 2);

        $this->assertEquals($valueArr[$separator + 1], count($valueArr) - $valueArr[3] - 5);
    }

    #[DataProvider('provideP1363Signatures')]
    public function testTranscodeSignatureToDERProducesCanonicalDer(string $p1363Hex, string $expectedDerHex): void
    {
        $this->assertSame(
            pack('H*', $expectedDerHex),
            AsnUtil::transcodeSignatureToDER(pack('H*', $p1363Hex))
        );
    }

    public static function provideP1363Signatures(): iterable
    {
        yield 'no padding required' => [
            '67ab34cd',
            '3008020267ab020234cd',
        ];

        yield 'positive sign padding required' => [
            'e7ab34cd',
            '3009020300e7ab020234cd',
        ];

        yield 'redundant leading zero must be stripped, required one kept' => [
            '006700e7',
            '3007020167020200e7',
        ];

        yield 'all-zero component remains valid INTEGER encoding' => [
            '00000000',
            '3006020100020100',
        ];
    }

    public function testTranscodeSignatureToDERUsesLongFormLengthForP521SizedSignature(): void
    {
        // Simulates a P-521 (ES512) raw P1363 signature whose components both
        // need a sign-protection byte, pushing the total DER content length
        // past 127 bytes and requiring a long-form outer SEQUENCE length.
        $component = str_repeat("\xff", 66);
        $p1363 = $component . $component;

        $result = AsnUtil::transcodeSignatureToDER($p1363);

        // 0x30, then long-form length: 0x81 followed by one length byte.
        $this->assertSame("\x30\x81\x8a", substr($result, 0, 3));
        $this->assertSame(3 + 0x8a, strlen($result));
        $this->assertTrue(AsnUtil::isSignatureInAsn1Format($result));
    }

    public function testIsSignatureInAsn1FormatRejectsRawP1363Signature(): void
    {
        $rawP1363 = str_repeat("\x01", 132);

        $this->assertFalse(AsnUtil::isSignatureInAsn1Format($rawP1363));
    }

    public function testIsSignatureInAsn1FormatAcceptsLongFormLengthSignature(): void
    {
        $component = str_repeat("\xff", 66);
        $der = AsnUtil::transcodeSignatureToDER($component . $component);

        $this->assertTrue(AsnUtil::isSignatureInAsn1Format($der));
    }

    public function testIsSignatureInAsn1FormatRejectsTruncatedSignature(): void
    {
        $component = str_repeat("\xff", 66);
        $der = AsnUtil::transcodeSignatureToDER($component . $component);

        $this->assertFalse(AsnUtil::isSignatureInAsn1Format(substr($der, 0, -1)));
    }
}
