<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\authtoken;

use UnexpectedValueException;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;

class WebEidAuthToken
{

    /**
     * @var string Unverified certificate
     */
    private ?string $unverifiedCertificate = null;
    /**
     * @var string Signature
     */
    private ?string $signature = null;
    /**
     * @var string Algorithm
     */
    private ?string $algorithm = null;
    /**
     * @var string Format
     */
    private ?string $format = null;

    public function __construct(string $authenticationTokenJSON)
    {
        $jsonDecoded = json_decode($authenticationTokenJSON, true);
        if (is_null($jsonDecoded)) {
            throw new AuthTokenParseException("Web eID authentication token is null");
        }

        // unverifiedCertificate
        if (isset($jsonDecoded['unverifiedCertificate'])) {
            $this->unverifiedCertificate = $this->filterString('unverifiedCertificate', $jsonDecoded['unverifiedCertificate']);
        }
        // algorithm
        if (isset($jsonDecoded['algorithm'])) {
            $this->algorithm = $this->filterString('algorithm', $jsonDecoded['algorithm']);
        }
        // signature
        if (isset($jsonDecoded['signature'])) {
            $this->signature = $this->filterString('signature', $jsonDecoded['signature']);
        }
        // format
        if (isset($jsonDecoded['format'])) {
            $this->format = $this->filterString('format', $jsonDecoded['format']);
        }
    }

    public function getUnverifiedCertificate(): ?string
    {
        return $this->unverifiedCertificate;
    }

    public function getAlgorithm(): ?string
    {
        return $this->algorithm;
    }

    public function getSignature(): ?string
    {
        return $this->signature;
    }

    public function getFormat(): ?string
    {
        return $this->format;
    }

    private function filterString(string $key, $data): string
    {
        $type = gettype($data);
        if ($type != "string") {
            throw new UnexpectedValueException("Error parsing Web eID authentication token: '{$key}' is {$type}, string expected");
        }
        return $data;
    }
}
