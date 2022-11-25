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

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspClient;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspRequestBuilder;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspResponseValidator;
use Throwable;
use web_eid\ocsp_php\Ocsp;
use web_eid\ocsp_php\OcspBasicResponse;
use web_eid\ocsp_php\OcspRequest;
use web_eid\ocsp_php\OcspResponse;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\OcspService;
use Psr\Log\LoggerInterface;

final class SubjectCertificateNotRevokedValidator implements SubjectCertificateValidator
{
    private $logger;

    private SubjectCertificateTrustedValidator $trustValidator;
    private OcspClient $ocspClient;
    private OcspServiceProvider $ocspServiceProvider;

    public function __construct(SubjectCertificateTrustedValidator $trustValidator, OcspClient $ocspClient, OcspServiceProvider $ocspServiceProvider, LoggerInterface $logger = null)
    {
        $this->logger = $logger;
        $this->trustValidator = $trustValidator;
        $this->ocspClient = $ocspClient;
        $this->ocspServiceProvider = $ocspServiceProvider;
    }

    public function validate(X509 $subjectCertificate): void
    {
        try {

            $ocspService = $this->ocspServiceProvider->getService($subjectCertificate);

            if (!$ocspService->doesSupportNonce()) {
                $this->logger?->debug("Disabling OCSP nonce extension");
            }

            $certificateId = (new Ocsp())->generateCertificateId($subjectCertificate, $this->trustValidator->getSubjectCertificateIssuerCertificate());
            $request = (new OcspRequestBuilder())->withCertificateId($certificateId)->enableOcspNonce($ocspService->doesSupportNonce())->build();

            $this->logger?->debug("Sending OCSP request");

            $response = $this->ocspClient->request($ocspService->getAccessLocation(), $request->getEncodeDer());

            if ($response->getStatus() != "successful") {
                throw new UserCertificateOCSPCheckFailedException("OCSP response status: " . $response->getStatus());
            }

            $this->verifyOcspResponse($response, $ocspService, $certificateId);

            if ($ocspService->doesSupportNonce()) {
                $this->checkNonce($request, $response->getBasicResponse());
            }
        } catch (Throwable $e) {
            throw new UserCertificateOCSPCheckFailedException("Exception: " . $e->getMessage(), $e);
        }
    }

    private function verifyOcspResponse(OcspResponse $response, OcspService $ocspService, array $requestCertificateId): void
    {
        $basicResponse = $response->getBasicResponse();

        // The verification algorithm follows RFC 2560, https://www.ietf.org/rfc/rfc2560.txt.
        //
        // 3.2.  Signed Response Acceptance Requirements
        //   Prior to accepting a signed response for a particular certificate as
        //   valid, OCSP clients SHALL confirm that:
        //
        //   1. The certificate identified in a received response corresponds to
        //      the certificate that was identified in the corresponding request.

        // As we sent the request for only a single certificate, we expect only a single response.
        if (count($basicResponse->getResponses()) != 1) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response must contain one response, received " . count($basicResponse->getResponses()) . " responses instead");
        }

        if ($requestCertificateId != $basicResponse->getCertID()) {
            throw new UserCertificateOCSPCheckFailedException("OCSP responded with certificate ID that differs from the requested ID");
        }

        //   2. The signature on the response is valid.

        // We assume that the responder includes its certificate in the certs field of the response
        // that helps us to verify it. According to RFC 2560 this field is optional, but including it
        // is standard practice.

        if (count($basicResponse->getCertificates()) < 1) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response must contain the responder certificate, but none was provided");
        }

        // The first certificate is the responder certificate, other certificates, if given, are the certificate's chain.
        $responderCert = $basicResponse->getCertificates()[0];

        OcspResponseValidator::validateResponseSignature($basicResponse, $responderCert);

        //   3. The identity of the signer matches the intended recipient of the
        //      request.
        //
        //   4. The signer is currently authorized to provide a response for the
        //      certificate in question.

        $producedAt = $basicResponse->getProducedAt();
        $ocspService->validateResponderCertificate($responderCert, $producedAt);

        //   5. The time at which the status being indicated is known to be
        //      correct (thisUpdate) is sufficiently recent.
        //
        //   6. When available, the time at or before which newer information will
        //      be available about the status of the certificate (nextUpdate) is
        //      greater than the current time.

        OcspResponseValidator::validateCertificateStatusUpdateTime($basicResponse, $producedAt);

        // Now we can accept the signed response as valid and validate the certificate status.
        OcspResponseValidator::validateSubjectCertificateStatus($response);

        $this->logger?->debug("OCSP check result is GOOD");
    }

    private static function checkNonce(OcspRequest $request, OcspBasicResponse $basicResponse): void
    {
        $requestNonce = $request->getNonceExtension();
        $responseNonce = $basicResponse->getNonceExtension();

        if ($requestNonce != $responseNonce) {
            throw new UserCertificateOCSPCheckFailedException("OCSP request and response nonces differ, possible replay attack");
        }
    }
}
