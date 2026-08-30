<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\util;

use DateTime;
use DateTimeZone;
use InvalidArgumentException;
use BadFunctionCallException;

final class DateAndTime
{

    /**
     * Don't call this, all functions are static.
     *
     * @throws BadFunctionCallException
     *
     * @return never
     */
    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    /**
     * Get current UTC time
     * 
     * @return DateTime
     */
    public static function utcNow(): DateTime
    {
        return new DateTime("now", new DateTimeZone("UTC"));
    }

    /**
     * Validates duration in seconds and
     * throws exception when duration is zero or below zero
     * 
     * @throws InvalidArgumentException
     */
    public static function requirePositiveDuration(int $duration, string $fieldName): void
    {
        if ($duration <= 0) {
            throw new InvalidArgumentException($fieldName . " must be greater than zero");
        }
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public static function toUtcString(?DateTime $date): string
    {
        if (is_null($date)) {
            return "null";
        }
        return ((clone $date)->setTimezone(new DateTimeZone("UTC")))->format("Y-m-d H:i:s e");
    }
}
