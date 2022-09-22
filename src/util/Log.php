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

final class Log
{
    private static string $name;

    public function __construct(string $name)
    {
        self::$name = $name;
    }

    public static function getLogger(string $name): Log
    {
        return new Log($name);
    }

    public static function debug($message)
    {
        return self::add($message, "debug");
    }

    public static function info($message)
    {
        return self::add($message, "info");
    }

    public static function warning($message)
    {
        return self::add($message, "warning");
    }

    public static function error($message)
    {
        return self::add($message, "error");
    }

    private static function add($message, $level)
    {

        // When command line interface and no logfile destination
        // defined, do not create log entry
        if ((php_sapi_name() == "cli") && !defined("LOGFILE")) {
            return;
        }

        $entry = [
            "timestamp" => time(),
            "name" => self::$name,
            "message" => $message,
            "level" => $level
        ];

        $line = self::formatEntry($entry);

        // When log file destination is not defined
        // put log in default logging destination
        if (!defined("LOGFILE")) {
            // Reformat entry, because timestamp included automatically
            $line = self::formatEntry($entry, false);
            error_log($line, 0);
            return;
        }

        error_log($line . PHP_EOL, 3, LOGFILE);
    }

    private static function formatEntry(array $entry, bool $withTimestamp = true): string
    {
        $logLine = "";
        if ($withTimestamp) {
            $logLine .= date("c", $entry["timestamp"]) . " ";
        }
        $logLine .= "[" . strtoupper($entry["level"]) . "] : ";
        if (!empty($entry["name"])) {
            $logLine .= $entry["name"] . " => ";
        }
        $logLine .= $entry["message"];
        return $logLine;
    }
}
