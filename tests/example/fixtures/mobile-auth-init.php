<?php

// Run the real handler in a subprocess because assertCsrf() terminates rejected requests.
require __DIR__ . '/../../../vendor/autoload.php';
require __DIR__ . '/../../../example/src/Config.php';
require __DIR__ . '/../../../example/src/AuthContext.php';
require __DIR__ . '/../../../example/src/MobileAuth.php';

$request = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$_SESSION = $request['session'];

function getallheaders(): array
{
    global $request;
    return $request['headers'];
}

http_response_code(200);
ob_start();
register_shutdown_function(function (): void {
    $body = ob_get_clean();
    echo json_encode([
        'status' => http_response_code(),
        'body' => $body,
        'session' => $_SESSION,
    ], JSON_THROW_ON_ERROR);
});

$config = Config::fromArray([
    'origin_url' => 'https://example.com',
    'mobile_base_url' => 'https://mopp.ria.ee',
    'mobile_request_signing_cert' => false,
]);
(new MobileAuth(new AuthContext($config)))->init();
