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
        throw new BadFunctionCallException('Utility class');
    }

    /**
     * Get current UTC time
     * 
     * @return DateTime
     */
    public static function utcNow(): DateTime
    {
        return new DateTime('now', new DateTimeZone('UTC'));
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
            throw new InvalidArgumentException($fieldName . ' must be greater than zero');
        }
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public static function toUtcString(?DateTime $date): string
    {
        if (is_null($date)) {
            return 'null';
        }
        return ((clone $date)->setTimezone(new DateTimeZone('UTC')))->format('Y-m-d H:i:s e');
    }
}

/**
 * @copyright 2022 Petr Muzikant pmuzikant@email.cz
 */
final class DefaultClock
{
    private static DefaultClock $instance;
    private DateTime $mockedClock;

    public static function getInstance()
    {
        if (!isset(self::$instance)) {
            self::$instance = new DefaultClock();
        }
        return self::$instance;
    }

    public function now(): DateTime
    {
        if (isset($this->mockedClock)) {
            return $this->mockedClock;
        }
        return new DateTime();
    }

    public function setClock(DateTime $mockedClock): void
    {
        $this->mockedClock = $mockedClock;
    }

    public function resetClock(): void
    {
        unset($this->mockedClock);
    }
}
