<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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

    public function __construct(int $ocspRequestTimeout, ?LoggerInterface $logger = null)
    {
        $this->requestTimeout = $ocspRequestTimeout;
        $this->logger = $logger;
    }

    public static function build(int $ocspRequestTimeout, ?LoggerInterface $logger = null): OcspClient
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
