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

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator;

use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNullOrEmptyException;
use InvalidArgumentException;
use web_eid\web_eid_authtoken_validation_php\util\AsnUtil;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenSignatureValidationException;

class AuthTokenSignatureValidator
{

    /** Supported subset of JSON Web Signature algorithms as defined in RFC 7518, sections 3.3, 3.4, 3.5.
     * See https://github.com/web-eid/libelectronic-id/blob/main/include/electronic-id/enums.hpp#L176.
     */
    private const ALLOWED_SIGNATURE_ALGORITHMS = [
        'ES256', 'ES384', 'ES512', // ECDSA
        'PS256', 'PS384', 'PS512', // RSASSA-PSS
        'RS256', 'RS384', 'RS512', // RSASSA-PKCS1-v1_5
    ];

    private Uri $siteOrigin;

    public function __construct(Uri $siteOrigin)
    {
        $this->siteOrigin = $siteOrigin;
    }

    public function validate(string $algorithm, string $signature, $publicKey, string $currentChallengeNonce): void
    {
        $this->requireNotEmpty($algorithm, "algorithm");
        $this->requireNotEmpty($signature, "signature");

        if (is_null($publicKey)) {
            throw new InvalidArgumentException("Public key is null");
        }

        if (empty($currentChallengeNonce)) {
            throw new ChallengeNullOrEmptyException();
        }

        if (!in_array($algorithm, self::ALLOWED_SIGNATURE_ALGORITHMS)) {
            throw new AuthTokenParseException("Invalid signature algorithm");
        }

        $decodedSignature = base64_decode($signature);

        // Note that in case of ECDSA, some eID cards output raw R||S, so we need to trascode it to DER
        if (in_array($algorithm, ["ES256", "ES384", "ES512"])) {
            $decodedSignature = AsnUtil::transcodeSignatureToDER($decodedSignature);
        }

        $hashAlgorithm = $this->hashAlgorithmForName($algorithm);

        $originHash = openssl_digest($this->siteOrigin->jsonSerialize(), $hashAlgorithm, true);
        $nonceHash = openssl_digest($currentChallengeNonce, $hashAlgorithm, true);
        $concatSignedFields = $originHash . $nonceHash;

        $result = openssl_verify($concatSignedFields, $decodedSignature, $publicKey, $hashAlgorithm);
        if (!$result) {
            throw new AuthTokenSignatureValidationException();
        }
    }

    private function hashAlgorithmForName(string $algorithm): string
    {
        return "sha" . substr($algorithm, -3);
    }

    private function requireNotEmpty(string $argument, string $fieldName): void
    {
        if (empty($argument)) {
            throw new AuthTokenParseException("'" . $fieldName . "' is null or empty");
        }
    }
}
