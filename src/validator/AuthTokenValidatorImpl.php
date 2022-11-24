<?php

/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\validator;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidatorBatch;
use Throwable;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateExpiryValidator;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificatePolicyValidator;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificatePurposeValidator;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateTrustedValidator;
use UnexpectedValueException;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateNotRevokedValidator;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClientImpl;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use Psr\Log\LoggerInterface;

final class AuthTokenValidatorImpl implements AuthTokenValidator
{

    private const TOKEN_MIN_LENGTH = 100;
    private const TOKEN_MAX_LENGTH = 10000;

    private AuthTokenValidationConfiguration $configuration;
    private SubjectCertificateValidatorBatch $simpleSubjectCertificateValidators;
    private AuthTokenSignatureValidator $authTokenSignatureValidator;
    private TrustedCertificates $trustedCACertificates;
    private $logger;

    private OcspClient $ocspClient;
    private OcspServiceProvider $ocspServiceProvider;

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public function __construct(AuthTokenValidationConfiguration $configuration, LoggerInterface $logger = null)
    {
        $this->logger = $logger;
        $this->configuration = $configuration;

        // Create trusted CA certificate objects for SubjectCertificateTrustedValidator and AiaOcspService.
        $this->trustedCACertificates = CertificateValidator::buildTrustFromCertificates($configuration->getTrustedCACertificates());

        $this->simpleSubjectCertificateValidators = new SubjectCertificateValidatorBatch(
            new SubjectCertificateExpiryValidator($this->trustedCACertificates, $logger),
            new SubjectCertificatePurposeValidator($logger),
            new SubjectCertificatePolicyValidator($this->configuration->getDisallowedSubjectCertificatePolicies(), $logger)
        );

        if ($this->configuration->isUserCertificateRevocationCheckWithOcspEnabled()) {
            $this->ocspClient = OcspClientImpl::build($this->configuration->getOcspRequestTimeout(), $logger);
            $this->ocspServiceProvider = new OcspServiceProvider(
                $this->configuration->getDesignatedOcspServiceConfiguration(),
                new AiaOcspServiceConfiguration(
                    $this->configuration->getNonceDisabledOcspUrls(),
                    $this->trustedCACertificates
                )
            );
        }

        $this->authTokenSignatureValidator = new AuthTokenSignatureValidator($this->configuration->getSiteOrigin());
    }

    private function validateTokenLength(string $authToken): void
    {
        if (is_null($authToken) || strlen($authToken) < self::TOKEN_MIN_LENGTH) {
            throw new AuthTokenParseException("Auth token is null or too short");
        }
        if (strlen($authToken) > self::TOKEN_MAX_LENGTH) {
            throw new AuthTokenParseException("Auth token is too long");
        }
    }

    public function parse(string $authToken): WebEidAuthToken
    {
        if ($this->logger) {
            $this->logger->info("Starting token parsing");
        }

        try {
            $this->validateTokenLength($authToken);
            return new WebEidAuthToken($authToken);
        } catch (Throwable $e) {
            if ($this->logger) {
                $this->logger->warning("Token parsing was interrupted: " . $e->getMessage());
            }
            throw $e;
        }
    }

    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce): X509
    {
        if ($this->logger) {
            $this->logger->info("Starting token validation");
        }

        try {
            return $this->validateToken($authToken, $currentChallengeNonce);
        } catch (Throwable $e) {
            if ($this->logger) {
                $this->logger->warning("Token validation was interrupted: " . $e->getMessage());
            }
            throw $e;
        }
    }

    private function validateToken(WebEidAuthToken $token, string $currentChallengeNonce): X509
    {
        if (is_null($token->getFormat()) || !str_starts_with($token->getFormat(), self::CURRENT_TOKEN_FORMAT_VERSION)) {
            throw new AuthTokenParseException("Only token format version '" . self::CURRENT_TOKEN_FORMAT_VERSION . "' is currently supported");
        }
        if (is_null($token->getUnverifiedCertificate()) || empty($token->getUnverifiedCertificate())) {
            throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
        }
        $subjectCertificate = new X509();
        if (!$subjectCertificate->loadX509($token->getUnverifiedCertificate())) {
            throw new CertificateDecodingException("'unverifiedCertificate' decode failed");
        }

        $this->simpleSubjectCertificateValidators->executeFor($subjectCertificate);
        $this->getCertTrustValidators()->executeFor($subjectCertificate);

        // It is guaranteed that if the signature verification succeeds, then the origin and challenge
        // have been implicitly and correctly verified without the need to implement any additional checks.

        $this->authTokenSignatureValidator->validate(
            $token->getAlgorithm(),
            $token->getSignature(),
            $subjectCertificate->getPublicKey(),
            $currentChallengeNonce
        );

        return $subjectCertificate;
    }

    private function getCertTrustValidators(): SubjectCertificateValidatorBatch
    {

        $certTrustedValidator = new SubjectCertificateTrustedValidator($this->trustedCACertificates, $this->logger);

        $validatorBatch = new SubjectCertificateValidatorBatch(
            $certTrustedValidator
        );

        if ($this->configuration->isUserCertificateRevocationCheckWithOcspEnabled()) {
            $validatorBatch->addOptional(
                $this->configuration->isUserCertificateRevocationCheckWithOcspEnabled(),
                new SubjectCertificateNotRevokedValidator($certTrustedValidator, $this->ocspClient, $this->ocspServiceProvider, $this->logger)
            );
        }

        return $validatorBatch;
    }
}
