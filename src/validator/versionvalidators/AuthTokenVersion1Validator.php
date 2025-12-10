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
use Throwable;
use web_eid\web_eid_authtoken_validation_php\authtoken\WebEidAuthToken;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidatorBatch;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateTrustedValidator;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateNotRevokedValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenSignatureValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidationConfiguration;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use Psr\Log\LoggerInterface;

class AuthTokenVersion1Validator implements AuthTokenVersionValidator
{
    private const V1_SUPPORTED_TOKEN_FORMAT_PREFIX = 'web-eid:1';

    private SubjectCertificateValidatorBatch $simpleSubjectCertificateValidators;
    private TrustedCertificates $trustedCACertificates;
    private AuthTokenSignatureValidator $authTokenSignatureValidator;
    private AuthTokenValidationConfiguration $configuration;
    private ?OcspClient $ocspClient;
    private ?OcspServiceProvider $ocspServiceProvider;
    private ?LoggerInterface $logger;

    public function __construct(
        SubjectCertificateValidatorBatch $simpleSubjectCertificateValidators,
        TrustedCertificates              $trustedCACertificates,
        AuthTokenSignatureValidator      $authTokenSignatureValidator,
        AuthTokenValidationConfiguration $configuration,
        ?OcspClient                      $ocspClient,
        ?OcspServiceProvider             $ocspServiceProvider,
        ?LoggerInterface                 $logger = null
    )
    {
        $this->simpleSubjectCertificateValidators = $simpleSubjectCertificateValidators;
        $this->trustedCACertificates = $trustedCACertificates;
        $this->authTokenSignatureValidator = $authTokenSignatureValidator;
        $this->configuration = $configuration;
        $this->ocspClient = $ocspClient;
        $this->ocspServiceProvider = $ocspServiceProvider;
        $this->logger = $logger;
    }

    public function supports(?string $format): bool
    {
        return $format !== null
            && str_starts_with($format, self::V1_SUPPORTED_TOKEN_FORMAT_PREFIX);
    }

    public function validate(WebEidAuthToken $authToken, string $currentChallengeNonce): X509
    {
        if ($authToken->getUnverifiedCertificate() === null ||
            $authToken->getUnverifiedCertificate() === '') {
            throw new AuthTokenParseException("'unverifiedCertificate' field is missing, null or empty");
        }

        $subjectCertificate = new X509();
        $loaded = false;

        try {
            $loaded = $subjectCertificate->loadX509($authToken->getUnverifiedCertificate());
        } catch (Throwable) {
        }

        if (!$loaded) {
            throw new CertificateDecodingException("'unverifiedCertificate' decode failed");
        }

        $this->simpleSubjectCertificateValidators->executeFor($subjectCertificate);
        $this->buildTrustValidatorBatch()->executeFor($subjectCertificate);

        $this->authTokenSignatureValidator->validate(
            $authToken->getAlgorithm(),
            $authToken->getSignature(),
            $subjectCertificate->getPublicKey(),
            $currentChallengeNonce
        );

        return $subjectCertificate;
    }

    private function buildTrustValidatorBatch(): SubjectCertificateValidatorBatch
    {
        $trustedValidator = new SubjectCertificateTrustedValidator(
            $this->trustedCACertificates,
            $this->logger
        );

        $batch = new SubjectCertificateValidatorBatch(
            $trustedValidator
        );

        if ($this->configuration->isUserCertificateRevocationCheckWithOcspEnabled()) {
            $batch->addOptional(
                true,
                new SubjectCertificateNotRevokedValidator(
                    $trustedValidator,
                    $this->ocspClient,
                    $this->ocspServiceProvider,
                    $this->configuration->getAllowedOcspResponseTimeSkew(),
                    $this->configuration->getMaxOcspResponseThisUpdateAge(),
                    $this->logger
                )
            );
        }

        return $batch;
    }
}
