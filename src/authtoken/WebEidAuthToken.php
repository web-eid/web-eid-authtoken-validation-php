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

namespace web_eid\web_eid_authtoken_validation_php\authtoken;

use UnexpectedValueException;

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
    /**
     * @var string App version
     */
    private ?string $appVersion = null;

    public function __construct(string $authenticationTokenJSON)
    {
        $jsonDecoded = json_decode($authenticationTokenJSON, true);
        if (is_null($jsonDecoded)) {
            return null;
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
        // appVersion
        if (isset($jsonDecoded['appVersion'])) {
            $this->appVersion = $this->filterString('appVersion', $jsonDecoded['appVersion']);
        }
    }

    public function getUnverifiedCertificate(): ?string
    {
        return $this->unverifiedCertificate;
    }

    public function setUnverifiedCertificate(string $unverifiedCertificate): void
    {
        $this->unverifiedCertificate = $unverifiedCertificate;
    }

    public function getAlgorithm(): ?string
    {
        return $this->algorithm;
    }

    public function setAlgorithm(string $algorithm): void
    {
        $this->algorithm = $algorithm;
    }

    public function getSignature(): ?string
    {
        return $this->signature;
    }

    public function setSignature(string $signature): void
    {
        $this->signature = $signature;
    }

    public function getFormat(): ?string
    {
        return $this->format;
    }

    public function setFormat(string $format): void
    {
        $this->format = $format;
    }

    public function getAppVersion(): ?string
    {
        return $this->appVersion;
    }

    private function filterString(string $key, $data): string
    {
        $type = gettype($data);
        if ($type != "string") {
            throw new UnexpectedValueException("'{$key}' is {$type}, string expected");
        }
        return $data;
    }
}
