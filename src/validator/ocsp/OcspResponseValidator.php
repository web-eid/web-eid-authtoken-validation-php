<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;
use DateInterval;
use web_eid\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\ocsp\OcspBasicResponse;
use web_eid\web_eid_authtoken_validation_php\ocsp\OcspResponse;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateOCSPCheckFailedException;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateRevokedException;
use web_eid\web_eid_authtoken_validation_php\util\DateAndTime;
use web_eid\web_eid_authtoken_validation_php\util\DefaultClock;

final class OcspResponseValidator
{

    /**
     * Indicates that a X.509 Certificates corresponding private key may be used by an authority to sign OCSP responses.
     * <p>
     * https://oidref.com/1.3.6.1.5.5.7.3.9.
     */
    private const OCSP_SIGNING = "id-kp-OCSPSigning";
    private const ERROR_PREFIX = "Certificate status update time check failed: ";
    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    public static function validateHasSigningExtension(X509 $certificate): void
    {
        if (!$certificate->getExtension("id-ce-extKeyUsage") || !in_array(self::OCSP_SIGNING, $certificate->getExtension("id-ce-extKeyUsage"))) {
            throw new OCSPCertificateException("Certificate " . $certificate->getSubjectDN(X509::DN_STRING) . " does not contain the key usage extension for OCSP response signing");
        }
    }

    public static function validateResponseSignature(OcspBasicResponse $basicResponse, X509 $responderCert): void
    {
        // get public key from responder certificate in order to verify signature on response
        $publicKey = $responderCert->getPublicKey()->withHash($basicResponse->getSignatureAlgorithm());
        // verify response data
        $encodedTbsResponseData = $basicResponse->getEncodedResponseData();
        $signature = $basicResponse->getSignature();

        if (!$publicKey->verify($encodedTbsResponseData, $signature)) {
            throw new UserCertificateOCSPCheckFailedException("OCSP response signature is invalid");
        }
    }

    public static function validateCertificateStatusUpdateTime(OcspBasicResponse $basicResponse, int $allowedOcspResponseTimeSkew, int $maxOcspResponseThisUpdateAge): void
    {
        // From RFC 2560, https://www.ietf.org/rfc/rfc2560.txt:
        // 4.2.2.  Notes on OCSP Responses
        // 4.2.2.1.  Time
        //   Responses whose nextUpdate value is earlier than
        //   the local system time value SHOULD be considered unreliable.
        //   Responses whose thisUpdate time is later than the local system time
        //   SHOULD be considered unreliable.
        //   If nextUpdate is not set, the responder is indicating that newer
        //   revocation information is available all the time.
        $now = DefaultClock::getInstance()->now();
        $earliestAcceptableTimeSkew = (clone $now)->sub(new DateInterval('PT' . $allowedOcspResponseTimeSkew . 'M'));
        $latestAcceptableTimeSkew = (clone $now)->add(new DateInterval('PT' . $allowedOcspResponseTimeSkew . 'M'));
        $minimumValidThisUpdateTime = (clone $now)->sub(new DateInterval('PT' . $maxOcspResponseThisUpdateAge . 'M'));

        $thisUpdate = $basicResponse->getThisUpdate();
        if ($thisUpdate > $latestAcceptableTimeSkew) {
            throw new UserCertificateOCSPCheckFailedException(self::ERROR_PREFIX .
                "thisUpdate '" . DateAndTime::toUtcString($thisUpdate) . "' is too far in the future, " .
                "latest allowed: '" . DateAndTime::toUtcString($latestAcceptableTimeSkew) . "'");
        }

        if ($thisUpdate < $minimumValidThisUpdateTime) {
            throw new UserCertificateOCSPCheckFailedException(self::ERROR_PREFIX .
                "thisUpdate '" . DateAndTime::toUtcString($thisUpdate) . "' is too old, " .
                "minimum time allowed: '" . DateAndTime::toUtcString($minimumValidThisUpdateTime) . "'");
        }

        $nextUpdate = $basicResponse->getNextUpdate();
        if (is_null($nextUpdate)) {
            return;
        }

        if ($nextUpdate < $earliestAcceptableTimeSkew) {
            throw new UserCertificateOCSPCheckFailedException(self::ERROR_PREFIX .
                "nextUpdate '" . DateAndTime::toUtcString($nextUpdate) . "' is in the past");
        }

        if ($nextUpdate < $thisUpdate) {
            throw new UserCertificateOCSPCheckFailedException(self::ERROR_PREFIX .
                "nextUpdate '" . DateAndTime::toUtcString($nextUpdate) . "' is before thisUpdate '" . DateAndTime::toUtcString($thisUpdate) . "'");
        }
    }

    public static function validateSubjectCertificateStatus(OcspResponse $response): void
    {
        if (is_null($response->isRevoked())) {
            throw new UserCertificateRevokedException("Unknown status");
        }
        if ($response->isRevoked() === false) {
            return;
        }
        if ($response->isRevoked() === true) {
            throw ($response->getRevokeReason() == "") ? new UserCertificateRevokedException() : new UserCertificateRevokedException("Revocation reason: " . $response->getRevokeReason());
        }
        throw new UserCertificateRevokedException("Status is neither good, revoked nor unknown");
    }
}
