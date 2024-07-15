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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use DateTime;
use DateInterval;
use PHPUnit\Framework\TestCase;
use web_eid\ocsp_php\OcspBasicResponse;
use web_eid\web_eid_authtoken_validation_php\util\DateAndTime;
use web_eid\web_eid_authtoken_validation_php\util\DefaultClock;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidationConfiguration;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;

class OcspResponseValidatorTest extends TestCase
{

    private static int $timeSkew;
    private static int $maxThisUpdateAge;

    protected function setUp(): void
    {
        $configuration = new AuthTokenValidationConfiguration();
        self::$timeSkew = $configuration->getAllowedOcspResponseTimeSkew();
        self::$maxThisUpdateAge = $configuration->getMaxOcspResponseThisUpdateAge();
    }

    public function testWhenThisAndNextUpdateWithinSkewThenValidationSucceeds(): void
    {
        $this->expectNotToPerformAssertions();

        $now = DefaultClock::getInstance()->now();
        $thisUpdateWithinAgeLimit = self::getThisUpdateWithinAgeLimit($now);
        $nextUpdateWithinAgeLimit = (clone $now)->add(new DateInterval('PT' . 2 . 'S'))->sub(new DateInterval('PT' . self::$maxThisUpdateAge . 'M'));
        $response = [];
        $response['tbsResponseData']['responses'] = [];
        $response['tbsResponseData']['responses'][] = [
            'thisUpdate' => $thisUpdateWithinAgeLimit->format('Y-m-d\TH:i:s.v\Z'),
            'nextUpdate' => $nextUpdateWithinAgeLimit->format('Y-m-d\TH:i:s.v\Z')
        ];
        $mockBasicResponse = new OcspBasicResponse($response);

        OcspResponseValidator::validateCertificateStatusUpdateTime($mockBasicResponse, self::$timeSkew, self::$maxThisUpdateAge);
    }

    public function testWhenNextUpdateBeforeThisUpdateThenThrows(): void
    {
        $now = DefaultClock::getInstance()->now();
        $thisUpdateWithinAgeLimit = self::getThisUpdateWithinAgeLimit($now);
        $beforeThisUpdate = (clone $thisUpdateWithinAgeLimit)->sub(new DateInterval('PT1S'));
        $response = [];
        $response['tbsResponseData']['responses'] = [];
        $response['tbsResponseData']['responses'][] = [
            'thisUpdate' => $thisUpdateWithinAgeLimit->format('Y-m-d\TH:i:s.v\Z'),
            'nextUpdate' => $beforeThisUpdate->format('Y-m-d\TH:i:s.v\Z')
        ];

        $mockBasicResponse = new OcspBasicResponse($response);

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: " .
            "Certificate status update time check failed: " .
            "nextUpdate '" . DateAndTime::toUtcString($beforeThisUpdate) . "' is before thisUpdate '" . DateAndTime::toUtcString($thisUpdateWithinAgeLimit) . "'");

        OcspResponseValidator::validateCertificateStatusUpdateTime($mockBasicResponse, self::$timeSkew, self::$maxThisUpdateAge);
    }

    public function testWhenThisUpdateHalfHourBeforeNowThenThrows(): void
    {
        $now = DefaultClock::getInstance()->now();
        $halfHourBeforeNow = (clone $now)->sub(new DateInterval('PT30M'));
        $response = [];
        $response['tbsResponseData']['responses'] = [];
        $response['tbsResponseData']['responses'][] = [
            'thisUpdate' => $halfHourBeforeNow->format('Y-m-d\TH:i:s.v\Z')
        ];

        $mockBasicResponse = new OcspBasicResponse($response);

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: " .
            "Certificate status update time check failed: " .
            "thisUpdate '" . DateAndTime::toUtcString($halfHourBeforeNow) . "' is too old, minimum time allowed: ");

        OcspResponseValidator::validateCertificateStatusUpdateTime($mockBasicResponse, self::$timeSkew, self::$maxThisUpdateAge);
    }

    public function testWhenThisUpdateHalfHourAfterNowThenThrows(): void
    {
        $now = DefaultClock::getInstance()->now();
        $halfHourAfterNow = (clone $now)->add(new DateInterval('PT30M'));
        $response = [];
        $response['tbsResponseData']['responses'] = [];
        $response['tbsResponseData']['responses'][] = [
            'thisUpdate' => $halfHourAfterNow->format('Y-m-d\TH:i:s.v\Z')
        ];

        $mockBasicResponse = new OcspBasicResponse($response);

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: " .
            "Certificate status update time check failed: " .
            "thisUpdate '" . DateAndTime::toUtcString($halfHourAfterNow) . "' is too far in the future, latest allowed: ");

        OcspResponseValidator::validateCertificateStatusUpdateTime($mockBasicResponse, self::$timeSkew, self::$maxThisUpdateAge);
    }

    public function testWhenNextUpdateHalfHourBeforeNowThenThrows(): void
    {
        $now = DefaultClock::getInstance()->now();
        $thisUpdateWithinAgeLimit = self::getThisUpdateWithinAgeLimit($now);
        $halfHourBeforeNow = (clone $now)->sub(new DateInterval('PT30M'));
        $response = [];
        $response['tbsResponseData']['responses'] = [];
        $response['tbsResponseData']['responses'][] = [
            'thisUpdate' => $thisUpdateWithinAgeLimit->format('Y-m-d\TH:i:s.v\Z'),
            'nextUpdate' => $halfHourBeforeNow->format('Y-m-d\TH:i:s.v\Z')
        ];

        $mockBasicResponse = new OcspBasicResponse($response);

        $this->expectException(UserCertificateOCSPCheckFailedException::class);
        $this->expectExceptionMessage("User certificate revocation check has failed: " .
            "Certificate status update time check failed: " .
            "nextUpdate '" . DateAndTime::toUtcString($halfHourBeforeNow) . "' is in the past");

        OcspResponseValidator::validateCertificateStatusUpdateTime($mockBasicResponse, self::$timeSkew, self::$maxThisUpdateAge);
    }

    private static function getThisUpdateWithinAgeLimit(DateTime $now): DateTime
    {
        return (clone $now)->add(new DateInterval('PT' . 1 . 'S'))->sub(new DateInterval('PT' . self::$maxThisUpdateAge . 'M'));
    }
}
