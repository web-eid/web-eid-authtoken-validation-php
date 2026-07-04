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

namespace web_eid\web_eid_authtoken_validation_php\authtoken;

use UnexpectedValueException;

class UnverifiedSigningCertificate
{
    /**
     * @var string Certificate
     */
    private ?string $certificate = null;

    /** @var SupportedSignatureAlgorithm[] */
    private array $supportedSignatureAlgorithms = [];

    /**
     * Unverified intermediate CA certificates of the signing certificate,
     * used only as candidate certificates during certification path building.
     *
     * @var string[]|null
     */
    private ?array $intermediateCertificates = null;

    public static function fromArray(array $data): self
    {
        $result = new self();

        if (isset($data['certificate'])) {
            $result->certificate = self::filterString('certificate', $data['certificate']);
        }

        if (isset($data['intermediateCertificates'])) {
            if (!is_array($data['intermediateCertificates'])) {
                $type = gettype($data['intermediateCertificates']);
                throw new UnexpectedValueException(
                    "Error parsing Web eID authentication token: " .
                    "'intermediateCertificates' is {$type}, array expected"
                );
            }

            $result->intermediateCertificates = self::parseIntermediateCertificates(
                $data['intermediateCertificates']
            );
        }

        if (isset($data['supportedSignatureAlgorithms'])) {
            if (!is_array($data['supportedSignatureAlgorithms'])) {
                $type = gettype($data['supportedSignatureAlgorithms']);
                throw new UnexpectedValueException(
                    "Error parsing Web eID authentication token: " .
                    "'supportedSignatureAlgorithms' is {$type}, array expected"
                );
            }

            $result->supportedSignatureAlgorithms = self::parseSupportedSignatureAlgorithms(
                $data['supportedSignatureAlgorithms']
            );
        }

        return $result;
    }

    public function getCertificate(): ?string
    {
        return $this->certificate;
    }

    public function getSupportedSignatureAlgorithms(): array
    {
        return $this->supportedSignatureAlgorithms;
    }

    /**
     * @return string[]|null
     */
    public function getIntermediateCertificates(): ?array
    {
        return $this->intermediateCertificates;
    }

    private static function filterString(string $key, $data): string
    {
        $type = gettype($data);
        if ($type !== 'string') {
            throw new UnexpectedValueException(
                "Error parsing Web eID authentication token: '{$key}' is {$type}, string expected"
            );
        }

        return $data;
    }

    /**
     * Entries are kept as-is (including null and empty strings); their content is
     * validated by the version validators with format-specific error messages.
     */
    private static function parseIntermediateCertificates(array $list): array
    {
        foreach ($list as $item) {
            if ($item !== null && !is_string($item)) {
                $type = gettype($item);
                throw new UnexpectedValueException(
                    "Error parsing Web eID authentication token: " .
                    "'intermediateCertificates' entry is {$type}, string expected"
                );
            }
        }

        return array_values($list);
    }

    private static function parseSupportedSignatureAlgorithms(array $list): array
    {
        $result = [];

        foreach ($list as $item) {
            if (!is_array($item)) {
                throw new UnexpectedValueException(
                    "Error parsing supportedSignatureAlgorithms: each item must be an object"
                );
            }

            $result[] = SupportedSignatureAlgorithm::fromArray($item);
        }

        return $result;
    }
}
