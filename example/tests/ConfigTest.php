<?php

use PHPUnit\Framework\TestCase;

class ConfigTest extends TestCase
{

    /**
     * @dataProvider localOriginHttpLoopbackAddress
     */
    public function testGivenLocalOriginHttpLoopbackAddressWhenParsingLocalOriginThenItIsReplacedWithHttps($origin) : void
    {
        $config = Config::fromArray(['origin_url' => $origin])->allowHttpOnLocalhost();
        $this->assertEquals($config->get('origin_url'), preg_replace('/^http:/', 'https:', $origin));
    }

    /**
     * @dataProvider localOriginHttpsLoopbackAddress
     */
    public function testGivenLocalOriginHttpsLoopbackAddressWhenParsingLocalOriginThenOriginalIsKept($origin) : void
    {
        $config = Config::fromArray(['origin_url' => $origin])->allowHttpOnLocalhost();
        $this->assertEquals($config->get('origin_url'), $origin);
    }

    /**
     * @dataProvider localOriginHttpNonLoopbackAddress
     */
    public function testGivenLocalOriginHttpNonLoopbackAddressWhenParsingLocalOriginThenOriginalIsKept($origin) : void
    {
        $config = Config::fromArray(['origin_url' => $origin])->allowHttpOnLocalhost();
        $this->assertEquals($config->get('origin_url'), $origin);
    }

    /**
     * @dataProvider localOriginEndingWithSlash
     */
    public function testGivenLocalOriginThatEndsWithSlashWhenParsingLocalOriginThenExceptionIsThrown($origin) : void
    {
        $this->expectExceptionMessage('Configuration parameter origin_url cannot end with \'/\'');
        Config::fromArray(['origin_url' => $origin])->allowHttpOnLocalhost();
    }

    public static function localOriginHttpLoopbackAddress(): array
    {
        return [
            ["http://localhost"],
            ["http://localhost:8080"],
            ["http://127.0.0.1"],
            ["http://127.0.0.1:8080"],
            ["http://[::1]"],
            ["http://[::1]:8080"]
        ];
    }

    public static function localOriginHttpsLoopbackAddress(): array
    {
        return [
            ["https://localhost"],
            ["https://localhost:8080"],
            ["https://127.0.0.1"],
            ["https://127.0.0.1:8080"],
            ["https://[::1]"],
            ["https://[::1]:8080"]
        ];
    }

    public static function localOriginHttpNonLoopbackAddress(): array
    {
        return [
            ["http://somename.app"],
            ["http://somename.app:8080"],
            ["http://8.8.8.8"],
            ["http://8.8.8.8:8080"],
            ["http://[2001:4860:4860::8888]"],
            ["http://[2001:4860:4860::8888]:8080"],
        ];
    }

    public static function localOriginEndingWithSlash(): array
    {
        return [
            ["https://localhost/"],
            ["https://localhost:8080/"]
        ];
    }
}
