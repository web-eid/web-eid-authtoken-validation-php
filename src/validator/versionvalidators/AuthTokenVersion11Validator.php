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

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\validator\versionvalidators;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\authtoken\SupportedSignatureAlgorithm;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateLoader;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenException;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;

class AuthTokenVersion11Validator extends AuthTokenVersion1Validator
{
    private const V11_SUPPORTED_TOKEN_FORMAT_PREFIX = "web-eid:1.1";

    private const SUPPORTED_SIGNING_CRYPTO_ALGORITHMS = ["ECC", "RSA"];
    private const SUPPORTED_SIGNING_PADDING_SCHEMES = [
        "NONE",
        "PKCS1.5",
        "PSS",
    ];
    private const SUPPORTED_SIGNING_HASH_FUNCTIONS = [
        "SHA-224",
        "SHA-256",
        "SHA-384",
        "SHA-512",
        "SHA3-224",
        "SHA3-256",
        "SHA3-384",
        "SHA3-512",
    ];

    public function supports(?string $format): bool
    {
        return $format !== null &&
            str_starts_with($format, self::V11_SUPPORTED_TOKEN_FORMAT_PREFIX);
    }

    /**
     * @throws AuthTokenParseException
     * @throws CertificateDecodingException
     * @throws AuthTokenException
     */
    public function validate(
        WebEidAuthToken $authToken,
        string $currentChallengeNonce,
    ): X509 {
        $subjectCertificate = $this->validateV1(
            $authToken,
            $currentChallengeNonce,
        );
        $signingCertificates = $this->validateSigningCertificates($authToken);

        foreach ($signingCertificates as $signingCertificate) {
            $this->validateSameSubject(
                $subjectCertificate,
                $signingCertificate,
            );
            $this->validateSameIssuer($subjectCertificate, $signingCertificate);
            $this->validateSigningCertificateValidity($signingCertificate);
            $this->validateKeyUsage($signingCertificate);
        }

        return $subjectCertificate;
    }

    /**
     * @return X509[]
     * @throws AuthTokenParseException
     * @throws CertificateDecodingException
     */
    private function validateSigningCertificates(WebEidAuthToken $token): array
    {
        $signingCertificates = $token->getUnverifiedSigningCertificates();

        if ($signingCertificates === null || empty($signingCertificates)) {
            throw new AuthTokenParseException(
                "'unverifiedSigningCertificates' field is missing, null or empty for format 'web-eid:1.1'",
            );
        }

        $result = [];

        foreach ($signingCertificates as $certificate) {
            if (
                $certificate === null ||
                $certificate->getCertificate() === null ||
                $certificate->getCertificate() === ""
            ) {
                throw new AuthTokenParseException(
                    "'unverifiedSigningCertificates' contains a null or empty entry for format 'web-eid:1.1'",
                );
            }

            $this->validateSupportedSignatureAlgorithms($certificate);
            $result[] = CertificateLoader::decodeCertificateFromBase64(
                $certificate->getCertificate(),
                "unverifiedSigningCertificates",
            );
        }

        return $result;
    }

    /**
     * @throws AuthTokenParseException
     */
    private function validateSupportedSignatureAlgorithms($cert): void
    {
        $algorithms = $cert->getSupportedSignatureAlgorithms();

        if ($algorithms === null || empty($algorithms)) {
            throw new AuthTokenParseException(
                "'supportedSignatureAlgorithms' field is missing",
            );
        }

        foreach ($algorithms as $alg) {
            if (
                !($alg instanceof SupportedSignatureAlgorithm) ||
                $alg->getCryptoAlgorithm() === null ||
                $alg->getHashFunction() === null ||
                $alg->getPaddingScheme() === null ||
                !in_array(
                    $alg->getCryptoAlgorithm(),
                    self::SUPPORTED_SIGNING_CRYPTO_ALGORITHMS,
                    true,
                ) ||
                !in_array(
                    $alg->getHashFunction(),
                    self::SUPPORTED_SIGNING_HASH_FUNCTIONS,
                    true,
                ) ||
                !in_array(
                    $alg->getPaddingScheme(),
                    self::SUPPORTED_SIGNING_PADDING_SCHEMES,
                    true,
                )
            ) {
                throw new AuthTokenParseException(
                    "Unsupported signature algorithm",
                );
            }
        }
    }

    /**
     * @throws AuthTokenParseException
     */
    private function validateSameSubject(
        X509 $subjectCert,
        X509 $signingCert,
    ): void {
        $sub = $subjectCert->getDN(true);
        $sig = $signingCert->getDN(true);

        ksort($sub);
        ksort($sig);

        if ($sub !== $sig) {
            throw new AuthTokenParseException(
                "Signing certificate subject does not match authentication certificate subject",
            );
        }
    }

    /**
     * @throws AuthTokenParseException
     */
    private function validateSameIssuer(
        X509 $subjectCert,
        X509 $signingCert,
    ): void {
        $subjectAki = $this->extractAuthorityKeyIdentifier($subjectCert);
        $signAki = $this->extractAuthorityKeyIdentifier($signingCert);

        if (empty($subjectAki) || empty($signAki) || $subjectAki !== $signAki) {
            throw new AuthTokenParseException(
                "Signing certificate is not issued by the same issuing authority as the authentication certificate",
            );
        }
    }

    /**
     * @throws AuthTokenParseException
     */
    private function validateSigningCertificateValidity(
        X509 $signingCertificate,
    ): void {
        $valid = $signingCertificate->validateDate();

        if ($valid !== true) {
            throw new AuthTokenParseException(
                "Signing certificate is not valid: {$valid}",
            );
        }
    }

    private function extractAuthorityKeyIdentifier(X509 $cert): string
    {
        $ext = $cert->getExtension("id-ce-authorityKeyIdentifier");
        return $ext["keyIdentifier"] ?? "";
    }

    private function validateKeyUsage(X509 $signingCertificate): void
    {
        $keyUsage = $signingCertificate->getExtension("id-ce-keyUsage");

        if (empty($keyUsage) || !in_array("nonRepudiation", $keyUsage, true)) {
            throw new AuthTokenParseException(
                "Signing certificate key usage extension missing or does not contain non-repudiation bit required for digital signatures",
            );
        }
    }

    /**
     * @throws AuthTokenException
     */
    protected function validateV1(
        WebEidAuthToken $token,
        string $currentChallengeNonce,
    ): X509 {
        return parent::validate($token, $currentChallengeNonce);
    }
}
