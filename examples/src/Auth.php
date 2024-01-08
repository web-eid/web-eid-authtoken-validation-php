<?php

/*
 * Copyright (c) 2022-2023 Estonian Information System Authority
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

use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateData;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateLoader;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceGenerator;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceGeneratorBuilder;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceStore;
use web_eid\web_eid_authtoken_validation_php\exceptions\ChallengeNonceExpiredException;
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidatorBuilder;
use phpseclib3\File\X509;

class Auth
{
    private $config;

    public function __construct($config) {
        $this->config = $config;
    }

    public function trustedIntermediateCACertificates(): array
    {
        return CertificateLoader::loadCertificatesFromResources(
            __DIR__ . "/../certificates/esteid2018.der.crt",
            __DIR__ . "/../certificates/ESTEID-SK_2015.der.crt"
        );
    }

    public function generator(): ChallengeNonceGenerator
    {
        return (new ChallengeNonceGeneratorBuilder())
            ->withNonceTtl(300)
            ->build();
    }

    public function tokenValidator(): AuthTokenValidator
    {
        $logger = new Logger();

        return (new AuthTokenValidatorBuilder($logger))
            ->withSiteOrigin(new Uri($this->config->get('origin_url')))
            ->withTrustedCertificateAuthorities(...self::trustedIntermediateCACertificates())
            ->build();
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
            $challengeNonce = $this->generator()->generateAndStoreNonce();
            $responseArr = ["nonce" => $challengeNonce->getBase64EncodedNonce()];
            echo json_encode($responseArr);
        } catch (Exception $e) {
            header("HTTP/1.0 500 Internal Server Error");
            echo "Nonce generation failed";
        }
    }

    private function getPrincipalNameFromCertificate(X509 $userCertificate): string
    {
        try {
            return CertificateData::getSubjectGivenName($userCertificate) . " " . CertificateData::getSubjectSurname($userCertificate);
        } catch (Exception $e) {
            return CertificateData::getSubjectCN($userCertificate);
        }
    }

    /**
     * Authenticate
     *
     * @return string
     */
    public function validate()
    {
        // Header names must be treated as case-insensitive (according to RFC2616) so we convert them to lowercase
        $headers = array_change_key_case(getallheaders(), CASE_LOWER);
        
        if (!isset($headers["x-csrf-token"]) || ($headers["x-csrf-token"] != $_SESSION["csrf-token"])) {
            header("HTTP/1.0 405 Method Not Allowed");
            echo "CSRF token missing, unable to process your request";
            return;
        }

        $authToken = file_get_contents("php://input");

        try {

            /* Get and remove nonce from store */
            $challengeNonce = (new ChallengeNonceStore())->getAndRemove();

            try {

                // Validate token
                $cert = $this->tokenValidator()->validate(new WebEidAuthToken($authToken), $challengeNonce->getBase64EncodedNonce());

                session_regenerate_id();

                $subjectName = $this->getPrincipalNameFromCertificate($cert);
                $result = [
                    "sub" => $subjectName
                ];

                $_SESSION["auth-user"] = $subjectName;

                echo json_encode($result);
            } catch (Exception $e) {
                header("HTTP/1.0 400 Bad Request");
                echo "Validation failed";
            }
        } catch (ChallengeNonceExpiredException $e) {
            header("HTTP/1.0 400 Bad Request");
            echo "Challenge nonce not found or expired";
        }
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
