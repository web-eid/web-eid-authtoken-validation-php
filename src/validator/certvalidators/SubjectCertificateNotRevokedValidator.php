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

namespace web_eid\web_eid_authtoken_validation_php\validator\certvalidators;

use lyquidity\OCSP\CertificateInfo;
use lyquidity\OCSP\CertificateLoader;
use lyquidity\OCSP\Response;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\util\Log;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspRequestBuilder;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;
use Throwable;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;

final class SubjectCertificateNotRevokedValidator implements SubjectCertificateValidator
{
    private Log $logger;

    private SubjectCertificateTrustedValidator $trustValidator;
    private OcspClient $ocspClient;
    private OcspServiceProvider $ocspServiceProvider;    

    public function __construct(SubjectCertificateTrustedValidator $trustValidator, OcspClient $ocspClient, OcspServiceProvider $ocspServiceProvider)
    {
        $this->logger = Log::getLogger(self::class);
        $this->trustValidator = $trustValidator;
        $this->ocspClient = $ocspClient;
        $this->ocspServiceProvider = $ocspServiceProvider;
    }

    public function validate(X509 $subjectCertificate): void
    {
        try {

            $ocspService = $this->ocspServiceProvider->getService($subjectCertificate);

            if (!$ocspService->doesSupportNonce()) {
                $this->logger->debug("Disabling OCSP nonce extension");
            }
    
            $certificateLoader = new CertificateLoader();

            // PEM encoded
            $certPem = $subjectCertificate->saveX509($subjectCertificate->getCurrentCert(), X509::FORMAT_PEM);
            $iss = $this->trustValidator->getSubjectCertificateIssuerCertificate();
            $issuerPem = $iss->saveX509($iss->getCurrentCert(), X509::FORMAT_PEM);

            $certificate = $certificateLoader->fromString($certPem);
            $issuerCertificate = $certificateLoader->fromString($issuerPem);
    
            // Extract the relevant data from the two certificates
            $certificateInfo = new CertificateInfo();
            $requestInfo = $certificateInfo->extractRequestInfo($certificate, $issuerCertificate);
    
            $request = (new OcspRequestBuilder())
                ->withCertificateId($requestInfo)
                ->enableOcspNonce($ocspService->doesSupportNonce())
                ->build();
    
            
            $this->logger->debug("Sending OCSP request");

            // TODO
            // Replace faulty OCSP library
            return;
    
            $response = $this->ocspClient->request($ocspService->getAccessLocation(), $request);
            $this->verifyOcspResponse($response);
            //$ocspResponderUrl = $certificateLoader->extractOcspResponderUrl($certificate);

        } catch (Throwable $e) {
            throw new UserCertificateOCSPCheckFailedException("Exception: " . $e->getMessage(), $e);
        }

    }

    private function verifyOcspResponse(Response $response): void
    {
        OcspResponseValidator::validateSubjectCertificateStatus($response);
    }

}
