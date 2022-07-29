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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;
use lyquidity\OCSP\Response;
use web_eid\web_eid_authtoken_validation_php\exceptions\OCSPCertificateException;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\exceptions\UserCertificateRevokedException;

final class OcspResponseValidator
{

/**
     * Indicates that a X.509 Certificates corresponding private key may be used by an authority to sign OCSP responses.
     * <p>
     * https://oidref.com/1.3.6.1.5.5.7.3.9.
     */
    private const OCSP_SIGNING = "id-kp-OCSPSigning";

    private const ALLOWED_TIME_SKEW = 15;

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }

    public static function validateHasSigningExtension(X509 $certificate): void
    {
        if (!$certificate->getExtension("id-ce-extKeyUsage") || !in_array(self::OCSP_SIGNING, $certificate->getExtension("id-ce-extKeyUsage"))) {
            throw new OCSPCertificateException("Certificate ".$certificate->getSubjectDN(X509::DN_STRING)." does not contain the key usage extension for OCSP response signing");
        }        
    }

    public static function validateResponseSignature()
    {

    }

    public static function validateCertificateStatusUpdateTime()
    {

    }

    public static function validateSubjectCertificateStatus(Response $certStatusResponse): void
    {
        // TODO
        // Selected lib does not support needed functionality and will be replaced
        return;
        if ($certStatusResponse->isRevoked() === false) {
            return;
        }
        if ($certStatusResponse->isRevoked() === true) {
            throw (is_null($certStatusResponse->getRevocationReason())) ? new UserCertificateRevokedException() : new UserCertificateRevokedException("Revocation reason: " . $certStatusResponse->getRevocationReason());
        }
        if (is_null($certStatusResponse->isRevoked())) {
            throw new UserCertificateRevokedException("Unknown status");
        }
        throw new UserCertificateRevokedException("Status is neither good, revoked nor unknown");
    }

}