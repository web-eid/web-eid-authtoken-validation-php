<?php

namespace web_eid\web_eid_authtoken_validation_php\util;

use BadFunctionCallException;

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

    public static function debug($message) {
        return self::add($message, "debug");
    }

    public static function info($message) {
        return self::add($message, "info");
    }

    public static function warning($message) {
        return self::add($message, "warning");
    }

    public static function error($message) {
        return self::add($message, "error");
    }

    private static function add($message, $level)
    {

        if (LOGFILE == false) {
            return;
        }

        $entry = [
            "timestamp" => time(),
            "name" => self::$name,
            "message" => $message,
            "level" => $level
        ];

       $line = self::formatEntry($entry);

       // Write to file
       $file = fopen(LOGFILE, "a");
       fwrite($file, $line . PHP_EOL);
       fclose($file);
    }

    private static function formatEntry(array $entry): string
    {
        $logLine = "";
        $logLine .= date("c", $entry["timestamp"] ) . " ";
        $logLine .= "[" . strtoupper($entry["level"]) . "] : ";
        if (!empty($entry["name"]) ) {
            $logLine .= $entry["name"] . " => ";
        }
        $logLine .= $entry["message"];            
        return $logLine;
    }
}