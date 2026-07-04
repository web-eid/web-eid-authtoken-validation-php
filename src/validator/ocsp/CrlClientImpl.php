<?php

/*
 * Copyright (c) 2026 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use GuzzleHttp\Psr7\Uri;
use Psr\Log\LoggerInterface;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateRevocationCheckFailedException;

class CrlClientImpl implements CrlClient
{
    private int $requestTimeout;
    private $logger;

    public function __construct(int $requestTimeout, ?LoggerInterface $logger = null)
    {
        $this->requestTimeout = $requestTimeout;
        $this->logger = $logger;
    }

    public static function build(int $requestTimeout, ?LoggerInterface $logger = null): CrlClient
    {
        return new CrlClientImpl($requestTimeout, $logger);
    }

    public function fetch(Uri $uri): string
    {
        $this->logger?->debug("Fetching CRL from " . $uri->jsonSerialize());

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $uri->jsonSerialize());
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FAILONERROR, true);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, $this->requestTimeout);
        curl_setopt($curl, CURLOPT_TIMEOUT, $this->requestTimeout);
        $result = curl_exec($curl);

        if (curl_errno($curl)) {
            throw new CertificateRevocationCheckFailedException(
                "CRL request failed: " . curl_error($curl)
            );
        }

        $info = curl_getinfo($curl);
        if ($info["http_code"] !== 200 || !is_string($result) || $result === "") {
            throw new CertificateRevocationCheckFailedException(
                "CRL request was not successful, HTTP status: " . $info["http_code"]
            );
        }

        return $result;
    }
}
