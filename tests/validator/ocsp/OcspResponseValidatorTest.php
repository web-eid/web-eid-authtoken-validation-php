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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use DateTime;
use PHPUnit\Framework\TestCase;
use web_eid\ocsp_php\OcspBasicResponse;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;

class OcspResponseValidatorTest extends TestCase
{

    public function testWhenThisUpdateDayBeforeProducedAtThenThrows(): void
    {
        $response = [];
        $response['tbsResponseData']['responses'] = [];
        $response['tbsResponseData']['responses'][] = ['thisUpdate' => '2021-09-01T00:00:00.000Z'];
        $mockBasicResponse = new OcspBasicResponse($response);

        $producedAt = new DateTime("2021-09-02T00:00:00.000Z");

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: " .
            "Certificate status update time check failed: " .
            "notAllowedBefore: 2021-09-01 23:59:45 UTC" .
            ", notAllowedAfter: 2021-09-02 00:00:15 UTC" .
            ", thisUpdate: 2021-09-01 00:00:00 UTC" .
            ", nextUpdate: null");

        OcspResponseValidator::validateCertificateStatusUpdateTime($mockBasicResponse, $producedAt);
    }

    public function testWhenThisUpdateDayAfterProducedAtThenThrows(): void
    {

        $response = [];
        $response['tbsResponseData']['responses'] = [];
        $response['tbsResponseData']['responses'][] = ['thisUpdate' => '2021-09-02T00:00:00.000Z'];
        $mockBasicResponse = new OcspBasicResponse($response);

        $producedAt = new DateTime("2021-09-01T00:00:00.000Z");

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: " .
            "Certificate status update time check failed: " .
            "notAllowedBefore: 2021-08-31 23:59:45 UTC" .
            ", notAllowedAfter: 2021-09-01 00:00:15 UTC" .
            ", thisUpdate: 2021-09-02 00:00:00 UTC" .
            ", nextUpdate: null");


        OcspResponseValidator::validateCertificateStatusUpdateTime($mockBasicResponse, $producedAt);
    }

    public function testWhenNextUpdateDayBeforeProducedAtThenThrows(): void
    {

        $response = [];
        $response['tbsResponseData']['responses'] = [];
        $response['tbsResponseData']['responses'][] = [
            'thisUpdate' => '2021-09-02T00:00:00.000Z',
            'nextUpdate' => '2021-09-01T00:00:00.000Z'
        ];
        $mockBasicResponse = new OcspBasicResponse($response);
        $producedAt = new DateTime("2021-09-02T00:00:00.000Z");

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: " .
            "Certificate status update time check failed: " .
            "notAllowedBefore: 2021-09-01 23:59:45 UTC" .
            ", notAllowedAfter: 2021-09-02 00:00:15 UTC" .
            ", thisUpdate: 2021-09-02 00:00:00 UTC" .
            ", nextUpdate: 2021-09-01 00:00:00 UTC");
        OcspResponseValidator::validateCertificateStatusUpdateTime($mockBasicResponse, $producedAt);
    }
}
