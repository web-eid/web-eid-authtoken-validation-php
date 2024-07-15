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