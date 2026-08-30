<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\util;

use DateTime;

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