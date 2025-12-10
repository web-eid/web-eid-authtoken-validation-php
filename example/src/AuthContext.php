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

use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateData;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateLoader;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceGenerator;
use web_eid\web_eid_authtoken_validation_php\challenge\ChallengeNonceGeneratorBuilder;
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidatorBuilder;
use phpseclib3\File\X509;

final class AuthContext
{
    public function __construct(private $config)
    {
    }

    public function originUrl(): string
    {
        return rtrim($this->config->get("origin_url"), "/");
    }

    public function mobileBaseUrl(): string
    {
        return rtrim($this->config->get("mobile_base_url"), "/");
    }

    public function mobileRequestSigningCert(): bool
    {
        return (bool) $this->config->get("mobile_request_signing_cert");
    }

    /**
     * @throws AuthTokenParseException
     */
    public function authenticate(
        string $authTokenJson,
        string $base64ChallengeNonce,
    ): array {
        $authToken = new WebEidAuthToken($authTokenJson);

        $cert = $this->tokenValidator()->validate(
            $authToken,
            $base64ChallengeNonce,
        );

        $firstSigningCertificate = null;
        $supportedSignatureAlgorithms = null;

        if (!empty($authToken->getUnverifiedSigningCertificates())) {
            $firstSigningCertificate = $authToken->getUnverifiedSigningCertificates()[0];

            if ($firstSigningCertificate !== null) {
                $supportedSignatureAlgorithms = $firstSigningCertificate->getSupportedSignatureAlgorithms();
                $firstSigningCertificate = $firstSigningCertificate->getCertificate();
            }
        }

        return [
            "subjectName" => $this->getPrincipalNameFromCertificate($cert),
            "signingCertificate" => $firstSigningCertificate,
            "supportedSignatureAlgorithms" => $supportedSignatureAlgorithms,
        ];
    }

    public function assertCsrf(bool $jsonError = true): void
    {
        $headers = array_change_key_case(getallheaders(), CASE_LOWER);

        if (
            !isset($headers["x-csrf-token"], $_SESSION["csrf-token"]) ||
            !hash_equals($_SESSION["csrf-token"], $headers["x-csrf-token"])
        ) {
            http_response_code(405);

            if ($jsonError) {
                echo json_encode(["error" => "CSRF token missing or invalid"]);
            } else {
                echo "CSRF token missing, unable to process your request";
            }

            exit();
        }
    }

    public function assertJsonContentType(bool $jsonError = true): void
    {
        $contentType = $_SERVER["CONTENT_TYPE"] ?? "";

        if (!str_starts_with(strtolower($contentType), "application/json")) {
            http_response_code(415);

            if ($jsonError) {
                echo json_encode([
                    "error" => "Content-Type must be application/json",
                ]);
            } else {
                echo "Invalid Content-Type, expected application/json";
            }
            exit();
        }
    }

    public function trustedIntermediateCACertificates(): array
    {
        $directory = __DIR__ . "/../certificates/";
        $certificates = glob($directory . "*.der.crt");
        return CertificateLoader::loadCertificatesFromResources(
            ...$certificates,
        );
    }

    public function nonceGenerator(): ChallengeNonceGenerator
    {
        return (new ChallengeNonceGeneratorBuilder())->withNonceTtl(300)->build();
    }

    public function tokenValidator(): AuthTokenValidator
    {
        $logger = new Logger();

        return (new AuthTokenValidatorBuilder($logger))
            ->withSiteOrigin(new Uri($this->config->get("origin_url")))
            ->withTrustedCertificateAuthorities(
                ...$this->trustedIntermediateCACertificates(),
            )
            ->build();
    }

    public function getPrincipalNameFromCertificate(X509 $cert): string
    {
        $givenName = CertificateData::getSubjectGivenName($cert);
        $surname = CertificateData::getSubjectSurname($cert);
        return $givenName && $surname
            ? "$givenName $surname"
            : CertificateData::getSubjectCN($cert);
    }
}
