<?php

/*
 * Copyright (c) 2026 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use DateInterval;
use DateTime;
use Exception;
use GuzzleHttp\Psr7\Uri;
use phpseclib3\File\X509;
use Psr\Log\LoggerInterface;
use web_eid\web_eid_authtoken_validation_php\certificate\IntermediateRevocationChecker;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateRevocationCheckFailedException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateRevokedException;
use web_eid\web_eid_authtoken_validation_php\ocsp\Ocsp;
use web_eid\web_eid_authtoken_validation_php\ocsp\OcspBasicResponse;
use web_eid\web_eid_authtoken_validation_php\util\DateAndTime;
use web_eid\web_eid_authtoken_validation_php\util\DefaultClock;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspService;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;

/**
 * Checks the revocation status of token-supplied intermediate CA certificates that are part
 * of a built certification path.
 *
 * OCSP via the certificate's AIA extension is preferred; when it is unavailable or
 * inconclusive, CRLs from the certificate's CRL distribution points are used as fallback.
 * A certificate that is revoked or whose status cannot be established fails the check.
 *
 * Unlike the user certificate OCSP check, no nonce is sent: CA OCSP responders commonly
 * serve pre-produced responses that do not support nonces, and the corresponding Java
 * implementation (the JDK PKIX revocation checker) does not send nonces either. For the
 * same reason the response freshness is validated against the thisUpdate/nextUpdate
 * validity window instead of the user certificate maximum response age policy.
 */
final class IntermediateRevocationCheckerImpl implements IntermediateRevocationChecker
{
    private OcspClient $ocspClient;
    private CrlClient $crlClient;
    private AiaOcspServiceConfiguration $aiaOcspServiceConfiguration;
    private int $allowedTimeSkew;
    private int $maxThisUpdateAge;
    private $logger;

    public function __construct(
        OcspClient $ocspClient,
        CrlClient $crlClient,
        AiaOcspServiceConfiguration $aiaOcspServiceConfiguration,
        int $allowedOcspResponseTimeSkew,
        int $maxOcspResponseThisUpdateAge,
        ?LoggerInterface $logger = null,
    ) {
        $this->ocspClient = $ocspClient;
        $this->crlClient = $crlClient;
        $this->aiaOcspServiceConfiguration = $aiaOcspServiceConfiguration;
        $this->allowedTimeSkew = $allowedOcspResponseTimeSkew;
        $this->maxThisUpdateAge = $maxOcspResponseThisUpdateAge;
        $this->logger = $logger;
    }

    public function validateNotRevoked(
        X509 $certificate,
        X509 $issuerCertificate,
        array $additionalIntermediateCertificates,
    ): void {
        $ocspFailure = null;

        if ($this->hasOcspUrl($certificate)) {
            try {
                $this->checkWithOcsp($certificate, $issuerCertificate, $additionalIntermediateCertificates);
                $this->logger?->debug("Intermediate CA certificate OCSP check result is GOOD");
                return;
            } catch (CertificateRevokedException $e) {
                // A definitive revoked status must not be overridden by a CRL fallback.
                throw $e;
            } catch (Exception $e) {
                $this->logger?->debug(
                    "Intermediate CA certificate OCSP check was inconclusive, " .
                    "falling back to CRL: " . $e->getMessage()
                );
                $ocspFailure = $e;
            }
        }

        $this->checkWithCrl($certificate, $issuerCertificate, $ocspFailure);
        $this->logger?->debug("Intermediate CA certificate CRL check result is GOOD");
    }

    private function hasOcspUrl(X509 $certificate): bool
    {
        try {
            return OcspUrl::getOcspUri($certificate) !== null;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * @param X509[] $additionalIntermediateCertificates
     */
    private function checkWithOcsp(
        X509 $certificate,
        X509 $issuerCertificate,
        array $additionalIntermediateCertificates,
    ): void {
        $ocspService = new AiaOcspService(
            $this->aiaOcspServiceConfiguration,
            $certificate,
            $issuerCertificate,
            $additionalIntermediateCertificates,
        );

        $certificateId = (new Ocsp())->generateCertificateId($certificate, $issuerCertificate);
        $request = (new OcspRequestBuilder())
            ->withCertificateId($certificateId)
            ->enableOcspNonce(false)
            ->build();

        $response = $this->ocspClient->request(
            $ocspService->getAccessLocation(),
            $request->getEncodeDer(),
        );

        if ($response->getStatus() != "successful") {
            throw new CertificateRevocationCheckFailedException(
                "OCSP response status: " . $response->getStatus()
            );
        }

        $basicResponse = $response->getBasicResponse();

        if (count($basicResponse->getResponses()) != 1) {
            throw new CertificateRevocationCheckFailedException(
                "OCSP response must contain one response, received " .
                count($basicResponse->getResponses()) . " responses instead"
            );
        }

        if (!OcspResponseValidator::certificateIdsMatch($certificateId, $basicResponse->getCertID())) {
            throw new CertificateRevocationCheckFailedException(
                "OCSP responded with certificate ID that differs from the requested ID"
            );
        }

        if (count($basicResponse->getCertificates()) < 1) {
            throw new CertificateRevocationCheckFailedException(
                "OCSP response must contain the responder certificate, but none was provided"
            );
        }

        $responderCert = $basicResponse->getCertificates()[0];
        OcspResponseValidator::validateResponseSignature($basicResponse, $responderCert);

        $now = DefaultClock::getInstance()->now();
        $ocspService->validateResponderCertificate($responderCert, $now);

        $this->validateOcspResponseTimes($basicResponse, $now);

        if ($response->isRevoked() === true) {
            $reason = $response->getRevokeReason();
            throw new CertificateRevokedException(
                "Intermediate CA certificate has been revoked" .
                ($reason == "" ? "" : ": Revocation reason: " . $reason)
            );
        }
        if ($response->isRevoked() !== false) {
            throw new CertificateRevocationCheckFailedException(
                "Intermediate CA certificate OCSP status is unknown"
            );
        }
    }

    /**
     * Validates that the current time is within the thisUpdate/nextUpdate validity window
     * of the OCSP response. When nextUpdate is absent, the user certificate maximum
     * response age policy is applied instead.
     */
    private function validateOcspResponseTimes(OcspBasicResponse $basicResponse, DateTime $now): void
    {
        $skew = new DateInterval('PT' . $this->allowedTimeSkew . 'M');

        $thisUpdate = $basicResponse->getThisUpdate();
        if ($thisUpdate > (clone $now)->add($skew)) {
            throw new CertificateRevocationCheckFailedException(
                "OCSP response thisUpdate '" . DateAndTime::toUtcString($thisUpdate) .
                "' is too far in the future"
            );
        }

        $nextUpdate = $basicResponse->getNextUpdate();
        if ($nextUpdate === null) {
            $minimumValidThisUpdateTime = (clone $now)
                ->sub(new DateInterval('PT' . $this->maxThisUpdateAge . 'M'));
            if ($thisUpdate < $minimumValidThisUpdateTime) {
                throw new CertificateRevocationCheckFailedException(
                    "OCSP response thisUpdate '" . DateAndTime::toUtcString($thisUpdate) . "' is too old"
                );
            }
            return;
        }

        if ($nextUpdate < (clone $now)->sub($skew)) {
            throw new CertificateRevocationCheckFailedException(
                "OCSP response nextUpdate '" . DateAndTime::toUtcString($nextUpdate) . "' is in the past"
            );
        }
    }

    private function checkWithCrl(
        X509 $certificate,
        X509 $issuerCertificate,
        ?Exception $ocspFailure,
    ): void {
        $urls = self::getCrlDistributionPointUrls($certificate);

        if ($urls === []) {
            throw new CertificateRevocationCheckFailedException(
                "Revocation status of the intermediate CA certificate could not be established: " .
                "no usable OCSP or CRL revocation source",
                $ocspFailure,
            );
        }

        $lastFailure = $ocspFailure;
        foreach ($urls as $url) {
            try {
                $this->validateWithCrlFrom($url, $certificate, $issuerCertificate);
                return;
            } catch (CertificateRevokedException $e) {
                throw $e;
            } catch (Exception $e) {
                $this->logger?->debug("CRL check via " . $url->jsonSerialize() . " failed: " . $e->getMessage());
                $lastFailure = $e;
            }
        }

        throw new CertificateRevocationCheckFailedException(
            "Revocation status of the intermediate CA certificate could not be established",
            $lastFailure,
        );
    }

    private function validateWithCrlFrom(Uri $url, X509 $certificate, X509 $issuerCertificate): void
    {
        $crlBytes = $this->crlClient->fetch($url);

        $crl = new X509();
        if (!$crl->loadCRL($crlBytes)) {
            throw new CertificateRevocationCheckFailedException("CRL decoding failed");
        }

        $crl->loadCA($issuerCertificate->saveX509($issuerCertificate->getCurrentCert(), X509::FORMAT_PEM));
        if ($crl->validateSignature() !== true) {
            throw new CertificateRevocationCheckFailedException(
                "CRL signature verification against the certificate issuer failed"
            );
        }

        $this->validateCrlTimes($crl, DefaultClock::getInstance()->now());

        $serialNumber = $certificate->getCurrentCert()['tbsCertificate']['serialNumber'];
        if ($crl->getRevoked($serialNumber->toString()) !== false) {
            throw new CertificateRevokedException(
                "Intermediate CA certificate has been revoked according to CRL"
            );
        }
    }

    private function validateCrlTimes(X509 $crl, DateTime $now): void
    {
        $tbsCertList = $crl->getCurrentCert()['tbsCertList'];
        $skew = new DateInterval('PT' . $this->allowedTimeSkew . 'M');

        $thisUpdateField = $tbsCertList['thisUpdate'];
        $thisUpdate = new DateTime($thisUpdateField['utcTime'] ?? $thisUpdateField['generalTime']);
        if ($thisUpdate > (clone $now)->add($skew)) {
            throw new CertificateRevocationCheckFailedException(
                "CRL thisUpdate '" . DateAndTime::toUtcString($thisUpdate) . "' is too far in the future"
            );
        }

        if (!isset($tbsCertList['nextUpdate'])) {
            throw new CertificateRevocationCheckFailedException("CRL nextUpdate is missing");
        }

        $nextUpdateField = $tbsCertList['nextUpdate'];
        $nextUpdate = new DateTime($nextUpdateField['utcTime'] ?? $nextUpdateField['generalTime']);
        if ($nextUpdate < (clone $now)->sub($skew)) {
            throw new CertificateRevocationCheckFailedException(
                "CRL nextUpdate '" . DateAndTime::toUtcString($nextUpdate) . "' is in the past"
            );
        }
    }

    /**
     * @return Uri[]
     */
    private static function getCrlDistributionPointUrls(X509 $certificate): array
    {
        $urls = [];
        $extension = $certificate->getExtension("id-ce-cRLDistributionPoints");
        if (!is_array($extension)) {
            return $urls;
        }

        foreach ($extension as $distributionPoint) {
            $fullNames = $distributionPoint["distributionPoint"]["fullName"] ?? [];
            foreach ($fullNames as $generalName) {
                $url = $generalName["uniformResourceIdentifier"] ?? null;
                if (is_string($url) && preg_match('/^https?:\/\//i', $url) === 1) {
                    $urls[] = new Uri($url);
                }
            }
        }

        return $urls;
    }
}
