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
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceNotFoundException;

final class Auth
{
    private AuthContext $ctx;
    private MobileAuth $mobile;

    public function __construct($config)
    {
        $this->ctx = new AuthContext($config);
        $this->mobile = new MobileAuth($this->ctx);
    }

    /**
     * Get challenge nonce
     *
     * @return string
     */
    public function getNonce()
    {
        try {
            header("Content-Type: application/json; charset=utf-8");
            $challengeNonce = $this->ctx
                ->nonceGenerator()
                ->generateAndStoreNonce();
            $responseArr = [
                "nonce" => $challengeNonce->getBase64EncodedNonce(),
            ];
            echo json_encode($responseArr);
        } catch (Exception $e) {
            http_response_code(500);
            echo "Nonce generation failed";
        }
    }

    /**
     * Authenticate
     *
     * @return string
     */
    public function validate()
    {
        $this->ctx->assertCsrf();
        $this->ctx->assertJsonContentType();
        $authToken = file_get_contents("php://input");

        try {
            /* Get and remove nonce from store */
            $challengeNonce = new ChallengeNonceStore()->getAndRemove();

            $authResult = $this->ctx->authenticate(
                $authToken,
                $challengeNonce->getBase64EncodedNonce(),
            );

            session_regenerate_id();
            $_SESSION["auth-user"] = $authResult["subjectName"];

            echo json_encode([
                "sub" => $authResult["subjectName"],
            ]);
        } catch (Exception $e) {
            unset($_SESSION["auth-user"]);
            http_response_code(401);

            $message = match (true) {
                $e instanceof ChallengeNonceExpiredException
                    => "Challenge nonce not found or expired",
                $e instanceof ChallengeNonceNotFoundException
                    => "Challenge nonce not found",
                $e instanceof AuthTokenParseException
                    => "Invalid authentication token",
                default => "Authentication failed: " . $e->getMessage(),
            };

            echo $message;
        }
    }

    /**
     * Mobile init (delegated)
     */
    public function mobileInit()
    {
        $this->mobile->init();
    }

    /**
     * Mobile login (delegated)
     */
    public function mobileLogin()
    {
        $this->mobile->login();
    }

    /**
     * Logout
     *
     */
    public function logout()
    {
        unset($_SESSION["auth-user"]);
        session_regenerate_id();
        // Redirect to login
        header("Location: /");
    }
}
