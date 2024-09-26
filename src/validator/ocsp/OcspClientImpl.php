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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\ocsp\OcspResponse;
use Psr\Log\LoggerInterface;

class OcspClientImpl implements OcspClient
{

    private const OCSP_REQUEST_TYPE = "application/ocsp-request";
    private const OCSP_RESPONSE_TYPE = "application/ocsp-response";
    private int $requestTimeout;
    private $logger;

    public function __construct(int $ocspRequestTimeout, LoggerInterface $logger = null)
    {
        $this->requestTimeout = $ocspRequestTimeout;
        $this->logger = $logger;
    }

    public static function build(int $ocspRequestTimeout, LoggerInterface $logger = null): OcspClient
    {
        return new OcspClientImpl($ocspRequestTimeout, $logger);
    }

    public function request(Uri $uri, string $encodedOcspRequest): OcspResponse
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $uri->jsonSerialize());
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FAILONERROR, true);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, ["Content-Type: " . self::OCSP_REQUEST_TYPE]);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $encodedOcspRequest);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, $this->requestTimeout);
        curl_setopt($curl, CURLOPT_TIMEOUT, $this->requestTimeout);
        $result = curl_exec($curl);

        if (curl_errno($curl)) {
            throw new UserCertificateOCSPCheckFailedException(curl_error($curl));
        }

        $info = curl_getinfo($curl);
        if ($info["http_code"] !== 200) {
            throw new UserCertificateOCSPCheckFailedException("OCSP request was not successful, response: " + $result);
        }

        $response = new OcspResponse($result);

        $responseJson = json_encode($response->getResponse(), JSON_INVALID_UTF8_IGNORE);
        $this->logger?->debug("OCSP response: " . $responseJson);

        if ($info["content_type"] !== self::OCSP_RESPONSE_TYPE) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response content type is not " . self::OCSP_RESPONSE_TYPE);
        }

        return $response;
    }
}
