<?php

/*
 * Copyright (c) 2022-2023 Estonian Information System Authority
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

use BadFunctionCallException;

final class AsnUtil
{

    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    public static function isSignatureInAsn1Format(string $signature): bool
    {
        $sigByteArray = unpack('C*', $signature);

        // ASN.1 format: 0x30 b1 0x02 b2 r 0x02 b3 s.
        // Note: unpack() returns an array indexed from 1, not 0.
        $b1 = $sigByteArray[2];
        $b2 = $sigByteArray[4];
        $b3 = $sigByteArray[6 + $b2];

        return $sigByteArray[1] == 0x30 // Sequence tag
            && $sigByteArray[3] == 0x02 // First integer tag
            && $sigByteArray[5 + $b2] == 0x02 // Second integer tag
            && count($sigByteArray) == 2 + $b1 // Length of contents
            && count($sigByteArray) == 6 + $b2 + $b3; // Total length
    }

    public static function transcodeSignatureToDER(string $p1363): string
    {
        // P1363 format: r followed by s.

        // ASN.1 format: 0x30 b1 0x02 b2 r 0x02 b3 s.
        //
        // r and s must be prefixed with 0x00 if their first byte is > 0x7f.
        //
        // b1 = length of contents.
        // b2 = length of r after being prefixed if necessary.
        // b3 = length of s after being prefixed if necessary.

        $asn1  = '';                        // ASN.1 contents.
        $len   = 0;                         // Length of ASN.1 contents.
        $c_len = intdiv(strlen($p1363), 2); // Length of each P1363 component.

        // Separate P1363 signature into its two equally sized components.
        foreach (str_split($p1363, $c_len) as $c) {
            // 0x02 prefix before each component.
            $asn1 .= "\x02";

            if (unpack('C', $c)[1] > 0x7f) {
                // Add 0x00 because first byte of component > 0x7f.
                // Length of component = ($c_len + 1).
                $asn1 .= pack('C', $c_len + 1) . "\x00";
                $len += 2 + ($c_len + 1);
            } else {
                $asn1 .= pack('C', $c_len);
                $len += 2 + $c_len;
            }

            // Append formatted component to ASN.1 contents.
            $asn1 .= $c;
        }

        // 0x30 b1, then contents.
        return "\x30" . pack('C', $len) . $asn1;
    }
}
