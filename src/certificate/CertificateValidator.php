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

namespace web_eid\web_eid_authtoken_validation_php\certificate;

use web_eid\web_eid_authtoken_validation_php\util\X509;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use BadFunctionCallException;
use DateTime;
use Exception;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotYetValidException;

final class CertificateValidator
{

    public function __construct()
    {
        throw new BadFunctionCallException('Utility class');
    }    

    public static function certificateIsValidOnDate(X509 $subjectCertificate, DateTime $date, string $subject): void
    {
        try {
            $subjectCertificate->checkValidity($date);
        } catch (Exception $e) {
            switch($e->getCode()) {
                // Not valid yet
                case 1:
                    throw new CertificateNotYetValidException($subject);
                    break;
                // Certificate is expired
                case 2:
                    throw new CertificateExpiredException($subject);
                    break;
                default:
                    throw new Exception($e->getMessage());    
            }
        }
    }

    public static function trustedCACertificatesAreValidOnDate(TrustedCertificates $trustedCertificates, DateTime $date): void
    {
        foreach($trustedCertificates->getCertificates() as $cert) {
            self::certificateIsValidOnDate($cert, $date, "Trusted CA");
        }
    }

    public static function validateIsSignedByTrustedCA(X509 $certificate, TrustedCertificates $trustedCertificates)
    {
        foreach ($trustedCertificates->getCertificates() as $trustedCertificate) {
            //
        }
    }

    public function buildTrustedCertificates(array $certificates): TrustedCertificates
    {
        return new TrustedCertificates($certificates);
    }

}