<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\testutil;

use DateTime;
use web_eid\web_eid_authtoken_validation_php\util\DefaultClock;

final class Dates
{
    public static function create(string $iso8601Date): DateTime
    {
        return new DateTime($iso8601Date);
    }

    public static function setMockedCertificateValidatorDate(DateTime $mockedDate): void
    {
        DefaultClock::getInstance()->setClock($mockedDate);
    }

    public static function resetMockedCertificateValidatorDate(): void
    {
        DefaultClock::getInstance()->resetClock();
    }
}
