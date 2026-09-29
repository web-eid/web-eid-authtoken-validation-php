<?php

namespace Tests;

use PHPUnit\Framework\TestCase;

class RouterTest extends TestCase
{
    private string $baseUrl = 'http://localhost:8888';
    private static $serverProcess;

    public static function setUpBeforeClass(): void
    {
        self::$serverProcess = proc_open(
            'php -S localhost:8888 -t ' . __DIR__ . '/../public',
            [],
            $pipes
        );

        // wait for server to start
        sleep(1);
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$serverProcess) {
            proc_terminate(self::$serverProcess);
            proc_close(self::$serverProcess);
        }
    }

    private function request(string $method, string $path, array $options = []): array
    {
        $ch = curl_init();

        curl_setopt_array($ch, [
                CURLOPT_URL            => $this->baseUrl . $path,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST  => $method,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_HEADER         => true,
                CURLOPT_COOKIEJAR      => '/tmp/test-cookies.txt',
                CURLOPT_COOKIEFILE     => '/tmp/test-cookies.txt',
            ] + $options);

        $response   = curl_exec($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $body       = substr($response, $headerSize);

        curl_close($ch);

        return [
            'status' => $response !== false ? $statusCode : 0,
            'body'   => $body,
        ];
    }

    public function testLoginPageReturns200(): void
    {
        $response = $this->request('GET', '/');

        $this->assertSame(200, $response['status']);
    }

    public function testNonceEndpointReturnsBody(): void
    {
        $response = $this->request('GET', '/nonce');

        $this->assertSame(200, $response['status']);
        $this->assertNotEmpty($response['body']);

        $data = json_decode($response['body'], true);
        $this->assertNotNull($data, 'Response should be valid JSON');
        $this->assertArrayHasKey('nonce', $data, 'Response should contain nonce field');
        $this->assertNotEmpty($data['nonce'], 'Nonce should not be empty');
        $this->assertSame(44, strlen($data['nonce']), 'Nonce should have size 44');
    }

    public function testWelcomePageReturnsUnauthorizedWhenNotLoggedIn(): void
    {
        $response = $this->request('GET', '/welcome');

        $this->assertContains(
            $response['status'],
            [301, 302, 401, 403],
            'Welcome page should not be accessible without authentication'
        );
    }
}
