<?php

/*
 * Copyright (c) 2025-2025 Estonian Information System Authority
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

use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceStore;

final class MobileAuth
{
    public function __construct(private AuthContext $ctx) {}

    public function init(): void
    {
        header("Content-Type: application/json; charset=utf-8");

        if (!isset($_SESSION["csrf-token"])) {
            $_SESSION["csrf-token"] = bin2hex(random_bytes(32));
        }

        $challenge = $this->ctx->nonceGenerator()->generateAndStoreNonce();

        $payload = [
            "challenge" => $challenge->getBase64EncodedNonce(),
            "login_uri" => $this->ctx->originUrl() . "/auth/mobile/login",
            "get_signing_certificate" => $this->ctx->mobileRequestSigningCert()
        ];

        $baseUrl = $this->ctx->mobileBaseUrl();
        $encodedPayload = base64_encode(json_encode($payload));

        if (str_starts_with($baseUrl, 'http')) {
            $authUri = rtrim($baseUrl, '/') . '/auth#' . $encodedPayload;
        } else {
            $authUri = rtrim($baseUrl, '/') . '//auth#' . $encodedPayload;
        }

        echo json_encode(["auth_uri" => $authUri]);
    }

    public function login(): void
    {
        $this->ctx->assertCsrf();
        $this->ctx->assertJsonContentType();

        $json = json_decode(file_get_contents("php://input"), true);
        if (!isset($json["auth_token"])) {
            http_response_code(400);
            echo json_encode(["error" => "Missing auth_token"]);
            return;
        }

        try {
            $nonce = (new ChallengeNonceStore())->getAndRemove();

            $this->ctx->authenticate(
                json_encode($json["auth_token"]),
                $nonce->getBase64EncodedNonce()
            );

            session_regenerate_id();

            echo json_encode(["redirect" => "/welcome"]);
        } catch (Throwable $e) {
            error_log("Authentication failed: " . $e->getMessage());

            unset($_SESSION["auth-user"]);

            http_response_code(401);
            echo json_encode(["error" => "Authentication failed"]);
        }
    }
}
