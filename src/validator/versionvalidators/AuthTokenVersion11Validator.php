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

use Exception;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\authtoken\SupportedSignatureAlgorithm;
use web_eid\web_eid_authtoken_validation_php\authtoken\UnverifiedSigningCertificate;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateLoader;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenException;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;

class AuthTokenVersion11Validator extends AuthTokenVersion1Validator
{
    private const V11_SUPPORTED_TOKEN_FORMAT_PATTERN = '/^web-eid:1\.1$/';

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
            preg_match(self::V11_SUPPORTED_TOKEN_FORMAT_PATTERN, $format) === 1;
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

        foreach ($this->validateSigningCertificates($authToken) as $unverifiedSigningCertificate) {
            $signingCertificate = CertificateLoader::decodeCertificateFromBase64(
                $unverifiedSigningCertificate->getCertificate(),
                "unverifiedSigningCertificates",
            );

            $this->validateSameSubject(
                $subjectCertificate,
                $signingCertificate,
            );
            $this->validateSameIssuer($subjectCertificate, $signingCertificate);
            $this->validateKeyUsage($signingCertificate);
            $this->validateSigningCertificateChain(
                $signingCertificate,
                CertificateLoader::decodeCertificatesFromBase64(
                    $unverifiedSigningCertificate->getIntermediateCertificates(),
                    "intermediateCertificates",
                ),
            );
        }

        return $subjectCertificate;
    }

    /**
     * @return UnverifiedSigningCertificate[]
     * @throws AuthTokenParseException
     */
    private function validateSigningCertificates(WebEidAuthToken $token): array
    {
        $signingCertificates = $token->getUnverifiedSigningCertificates();
        $intermediateCertificates = $token->getUnverifiedIntermediateCertificates();

        // When the authentication certificate's intermediate certificates are present,
        // signing certificates are optional.
        if (
            $signingCertificates === null &&
            $intermediateCertificates !== null &&
            $intermediateCertificates !== []
        ) {
            return [];
        }

        if ($signingCertificates === null || $signingCertificates === []) {
            throw new AuthTokenParseException(
                "'unverifiedSigningCertificates' field is missing, null or empty for format 'web-eid:1.1'",
            );
        }

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
            self::validateIntermediateCertificatesField(
                $certificate->getIntermediateCertificates(),
                "intermediateCertificates",
                $token->getFormat(),
            );
        }

        return $signingCertificates;
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
                "Signing certificate key usage extension missing or does not " .
                "contain non-repudiation bit required for digital signatures",
            );
        }
    }

    /**
     * @param X509[] $intermediateCertificates
     * @throws AuthTokenParseException
     */
    private function validateSigningCertificateChain(
        X509 $signingCertificate,
        array $intermediateCertificates,
    ): void {
        try {
            // The signing certificate itself deliberately gets no revocation check during
            // authentication: its revocation status matters at signing time and is the
            // signature validation service's concern. Token-supplied intermediate
            // certificates in its path are checked for revocation.
            CertificateValidator::validateIsValidAndSignedByTrustedCA(
                $signingCertificate,
                $this->trustedCACertificates,
                "Signing",
                $intermediateCertificates,
                $this->intermediateRevocationChecker,
            );
        } catch (Exception $e) {
            throw new AuthTokenParseException(
                "Signing certificate chain validation failed",
                $e,
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
