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

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp;

use phpseclib3\File\ASN1;
use UnexpectedValueException;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspResponseDecodeException;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspVerifyFailedException;
use web_eid\web_eid_authtoken_validation_php\ocsp\maps\OcspBasicResponseMap;
use web_eid\web_eid_authtoken_validation_php\ocsp\maps\OcspResponseMap;

class OcspResponse
{
    private array $ocspResponse = [];
    private string $revokeReason = "";

    public function __construct(string $encodedBER)
    {
        $decoded = self::getDecoded($encodedBER);

        $this->ocspResponse = ASN1::asn1map($decoded[0], OcspResponseMap::MAP, [
            "response" => function ($encoded) {
                return ASN1::asn1map(
                    self::getDecoded($encoded)[0],
                    OcspBasicResponseMap::MAP
                );
            },
        ]);
    }

    public function getResponse(): array
    {
        return $this->ocspResponse;
    }

    public function getBasicResponse(): OcspBasicResponse
    {
        if (
            Ocsp::ID_PKIX_OCSP_BASIC_STRING !=
            $this->ocspResponse["responseBytes"]["responseType"]
        ) {
            throw new UnexpectedValueException(
                'responseType is not "id-pkix-ocsp-basic" but is ' .
                    $this->ocspResponse["responseBytes"]["responseType"]
            );
        }

        if (!$this->ocspResponse["responseBytes"]["response"]) {
            throw new UnexpectedValueException(
                "Could not decode OcspResponse->responseBytes->response"
            );
        }

        return new OcspBasicResponse(
            $this->ocspResponse["responseBytes"]["response"]
        );
    }

    public function getStatus(): string
    {
        return $this->ocspResponse["responseStatus"];
    }

    public function getRevokeReason(): string
    {
        return $this->revokeReason;
    }

    public function isRevoked()
    {
        $basicResponse = $this->getBasicResponse();
        $this->validateResponse($basicResponse);

        if (isset($basicResponse->getResponses()[0]["certStatus"]["good"])) {
            return false;
        }
        if (isset($basicResponse->getResponses()[0]["certStatus"]["revoked"])) {
            $revokedStatus = $basicResponse->getResponses()[0]["certStatus"][
                "revoked"
            ];
            // Check revoke reason
            if (isset($revokedStatus["revokedReason"])) {
                $this->revokeReason = $revokedStatus["revokedReason"];
            }
            return true;
        }
        return null;
    }

    public function validateSignature(): void
    {
        $basicResponse = $this->getBasicResponse();
        $this->validateResponse($basicResponse);

        $responderCert = $basicResponse->getCertificates()[0];
        // get public key from responder certificate in order to verify signature on response
        $publicKey = $responderCert
            ->getPublicKey()
            ->withHash($basicResponse->getSignatureAlgorithm());
        // verify response data
        $encodedTbsResponseData = $basicResponse->getEncodedResponseData();
        $signature = $basicResponse->getSignature();

        if (!$publicKey->verify($encodedTbsResponseData, $signature)) {
            throw new OcspVerifyFailedException(
                "OCSP response signature is not valid"
            );
        }
    }

    public function validateCertificateId(array $requestCertificateId): void
    {
        $basicResponse = $this->getBasicResponse();
        if ($requestCertificateId != $basicResponse->getCertID()) {
            throw new OcspVerifyFailedException(
                "OCSP responded with certificate ID that differs from the requested ID"
            );
        }
    }

    private function validateResponse(OcspBasicResponse $basicResponse): void
    {
        // Must be one response
        if (count($basicResponse->getResponses()) != 1) {
            throw new OcspVerifyFailedException(
                "OCSP response must contain one response, received " .
                    count($basicResponse->getResponses()) .
                    " responses instead"
            );
        }

        // At least on cert must exist in responder
        if (count($basicResponse->getCertificates()) < 1) {
            throw new OcspVerifyFailedException(
                "OCSP response must contain the responder certificate, but none was provided"
            );
        }
    }

    private static function getDecoded(string $encodedBER) {
        $decoded = ASN1::decodeBER($encodedBER);
        if (!is_array($decoded)) {
            throw new OcspResponseDecodeException();
        }
        return $decoded;
    }
}
