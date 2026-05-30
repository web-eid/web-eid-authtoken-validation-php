<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
