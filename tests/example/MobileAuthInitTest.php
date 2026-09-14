<?php

namespace web_eid\web_eid_authtoken_validation_php\example;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonce;

final class MobileAuthInitTest extends TestCase
{
    public static function csrfRequests(): array
    {
        return [
            'missing header' => [[], ['csrf-token' => 'expected'], false],
            'incorrect token' => [['X-CSRF-TOKEN' => 'wrong'], ['csrf-token' => 'expected'], false],
            'missing session token' => [['X-CSRF-TOKEN' => 'expected'], [], false],
            'matching token' => [['X-CSRF-TOKEN' => 'expected'], ['csrf-token' => 'expected'], true],
        ];
    }

    #[DataProvider('csrfRequests')]
    public function testInitializationRequiresCsrfToken(array $headers, array $session, bool $accepted): void
    {
        // A rejected request must not replace an outstanding authentication challenge.
        $session['web-eid-challenge-nonce'] = 'existing challenge';
        $process = proc_open(
            [PHP_BINARY, __DIR__ . '/fixtures/mobile-auth-init.php'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        self::assertIsResource($process);
        fwrite($pipes[0], json_encode(['headers' => $headers, 'session' => $session], JSON_THROW_ON_ERROR));
        fclose($pipes[0]);
        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        self::assertSame(0, proc_close($process), $errors);
        self::assertSame('', $errors);
        $result = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        $body = json_decode($result['body'], true, 512, JSON_THROW_ON_ERROR);

        if (!$accepted) {
            self::assertSame(405, $result['status']);
            self::assertSame(['error' => 'CSRF token missing or invalid'], $body);
            self::assertSame($session, $result['session']);
            return;
        }

        self::assertSame(200, $result['status']);
        self::assertSame($session['csrf-token'], $result['session']['csrf-token']);
        self::assertStringStartsWith('https://mopp.ria.ee/auth#', $body['authUri']);
        $payload = json_decode(base64_decode(explode('#', $body['authUri'], 2)[1]), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame('https://example.com/auth/mobile/login', $payload['loginUri']);
        self::assertFalse($payload['getSigningCertificate']);
        $nonce = unserialize($result['session']['web-eid-challenge-nonce'], [
            'allowed_classes' => [ChallengeNonce::class, \DateTime::class],
        ]);
        self::assertInstanceOf(ChallengeNonce::class, $nonce);
        self::assertSame($nonce->getBase64EncodedNonce(), $payload['challenge']);
    }
}
