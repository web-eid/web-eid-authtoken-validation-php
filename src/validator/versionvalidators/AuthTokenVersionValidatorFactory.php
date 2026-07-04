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

use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificateValidatorBatch;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificatePurposeValidator;
use web_eid\web_eid_authtoken_validation_php\validator\certvalidators\SubjectCertificatePolicyValidator;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\CrlClientImpl;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\IntermediateRevocationCheckerImpl;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClientImpl;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenSignatureValidator;
use web_eid\web_eid_authtoken_validation_php\validator\AuthTokenValidationConfiguration;
use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\exceptions\AuthTokenParseException;
use Psr\Log\LoggerInterface;

final class AuthTokenVersionValidatorFactory
{
    /** @var AuthTokenVersionValidator[] */
    private array $validators;

    /**
     * @param AuthTokenVersionValidator[] $validators
     */
    public function __construct(array $validators)
    {
        $this->validators = $validators;
    }

    public function supports(?string $format): bool
    {
        foreach ($this->validators as $validator) {
            if ($validator->supports($format)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @throws AuthTokenParseException
     */
    public function getValidatorFor(?string $format): AuthTokenVersionValidator
    {
        foreach ($this->validators as $validator) {
            if ($validator->supports($format)) {
                return $validator;
            }
        }

        $formatLabel = $format ?? "null";
        throw new AuthTokenParseException(
            "Token format version '{$formatLabel}' is currently not supported"
        );
    }

    public static function create(
        AuthTokenValidationConfiguration $configuration,
        ?OcspClient $providedOcspClient,
        ?LoggerInterface $logger = null
    ): self {
        $validationConfig = clone $configuration;

        $trustedCACertificates = CertificateValidator::buildTrustFromCertificates(
            $validationConfig->getTrustedCACertificates()
        );

        $simpleSubjectCertificateValidators = new SubjectCertificateValidatorBatch(
            new SubjectCertificatePurposeValidator($logger),
            new SubjectCertificatePolicyValidator(
                $validationConfig->getDisallowedSubjectCertificatePolicies(),
                $logger
            )
        );

        $aiaOcspServiceConfiguration = new AiaOcspServiceConfiguration(
            $validationConfig->getNonceDisabledOcspUrls(),
            $trustedCACertificates
        );

        // The OCSP client is needed even when the user certificate revocation check is
        // disabled: token-supplied intermediate CA certificates are always checked for
        // revocation when they are part of a built certification path.
        $ocspClient = $providedOcspClient ?? OcspClientImpl::build(
            $validationConfig->getOcspRequestTimeout(),
            $logger
        );

        $intermediateRevocationChecker = new IntermediateRevocationCheckerImpl(
            $ocspClient,
            CrlClientImpl::build($validationConfig->getOcspRequestTimeout(), $logger),
            $aiaOcspServiceConfiguration,
            $validationConfig->getAllowedOcspResponseTimeSkew(),
            $validationConfig->getMaxOcspResponseThisUpdateAge(),
            $logger
        );

        $ocspServiceProvider = null;

        if ($validationConfig->isUserCertificateRevocationCheckWithOcspEnabled()) {
            $ocspServiceProvider = new OcspServiceProvider(
                $validationConfig->getDesignatedOcspServiceConfiguration(),
                $aiaOcspServiceConfiguration
            );
        }

        $authTokenSignatureValidator = new AuthTokenSignatureValidator(
            $validationConfig->getSiteOrigin()
        );

        $validator11 = new AuthTokenVersion11Validator(
            $simpleSubjectCertificateValidators,
            $trustedCACertificates,
            $authTokenSignatureValidator,
            $validationConfig,
            $ocspClient,
            $ocspServiceProvider,
            $logger,
            $intermediateRevocationChecker
        );

        $validator1 = new AuthTokenVersion1Validator(
            $simpleSubjectCertificateValidators,
            $trustedCACertificates,
            $authTokenSignatureValidator,
            $validationConfig,
            $ocspClient,
            $ocspServiceProvider,
            $logger,
            $intermediateRevocationChecker
        );

        return new self([
            $validator11,
            $validator1
        ]);
    }
}
