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

use BadFunctionCallException;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\SubjectPublicKeyInfo;

final class AsnUtil
{
    public const ID_PKIX_OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";

    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    public static function isSignatureInAsn1Format(string $signature): bool
    {
        $sigByteArray = unpack('C*', $signature);

        // ASN.1 format: 0x30 b1 0x02 b2 r 0x02 b3 s.
        // Note: unpack() returns an array indexed from 1, not 0.
        if(!isset($sigByteArray[1]) ||
            !isset($sigByteArray[2]) ||
            !isset($sigByteArray[3]) ||
            !isset($sigByteArray[4])) {
            return false;
        }
        $b1 = $sigByteArray[2];
        $b2 = $sigByteArray[4];
        if(!isset($sigByteArray[5 + $b2]) ||
            !isset($sigByteArray[6 + $b2])) {
            return false;
        }
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

    public static function loadOIDs(): void
    {
        ASN1::loadOIDs([
            "id-pkix-ocsp-nonce" => self::ID_PKIX_OCSP_NONCE,
            "id-sha1" => "1.3.14.3.2.26",
            "sha256WithRSAEncryption" => "1.2.840.113549.1.1.11",
            "qcStatements(3)" => "1.3.6.1.5.5.7.1.3",
            "street" => "2.5.4.9",
            "id-pkix-ocsp-basic" => "1.3.6.1.5.5.7.48.1.1",
            "id-pkix-ocsp" => "1.3.6.1.5.5.7.48.1",
            "secp384r1" => "1.3.132.0.34",
            "id-pkix-ocsp-archive-cutoff" => "1.3.6.1.5.5.7.48.1.6",
            "id-pkix-ocsp-nocheck" => "1.3.6.1.5.5.7.48.1.5",
        ]);
    }

    public static function extractKeyData(string $publicKey): string
    {
        $extractedBER = ASN1::extractBER($publicKey);
        $decodedBER = ASN1::decodeBER($extractedBER);
        $subjectPublicKey = ASN1::asn1map(
            $decodedBER[0],
            SubjectPublicKeyInfo::MAP
        )["subjectPublicKey"];
        // Remove first byte
        return pack("c*", ...array_slice(unpack("c*", $subjectPublicKey), 1));
    }

    public static function decodeNonceExtension(array $ocspExtensions): ?string
    {
        $nonceExtension = current(
            array_filter(
                $ocspExtensions,
                function ($extension) {
                    return self::ID_PKIX_OCSP_NONCE == ASN1::getOID($extension["extnId"]);
                }
            )
        );
        if (!$nonceExtension || !isset($nonceExtension["extnValue"])) {
            return null;
        }

        $nonceValue = $nonceExtension["extnValue"];

        $decoded = ASN1::decodeBER($nonceValue);
        if (is_array($decoded)) {
            // The value was DER-encoded, it is required to be an octet string.
            $nonceString = ASN1::asn1map($decoded[0], ['type' => ASN1::TYPE_OCTET_STRING]);
            return is_string($nonceString) ? $nonceString : null;
        }

        // The value was not DER-encoded, return it as-is.
        return $nonceValue;
    }
}
