<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\certificate;

use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\util\TrustedCertificates;
use BadFunctionCallException;
use DateTime;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateExpiredException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotYetValidException;
use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateNotTrustedException;

final class CertificateValidator
{

    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public static function certificateIsValidOnDate(X509 $subjectCertificate, DateTime $date, string $subject): void
    {
        if (!$subjectCertificate->validateDate($date)) {

            if ($date < new DateTime($subjectCertificate->getCurrentCert()['tbsCertificate']['validity']['notBefore']['utcTime'])) {
                throw new CertificateNotYetValidException($subject);
            }

            if ($date > new DateTime($subjectCertificate->getCurrentCert()['tbsCertificate']['validity']['notAfter']['utcTime'])) {
                throw new CertificateExpiredException($subject);
            }
        }
    }

    public static function trustedCACertificatesAreValidOnDate(TrustedCertificates $trustedCertificates, DateTime $date): void
    {
        foreach ($trustedCertificates->getCertificates() as $cert) {
            self::certificateIsValidOnDate($cert, $date, "Trusted CA");
        }
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public static function validateIsSignedByTrustedCA(X509 $certificate, TrustedCertificates $trustedCertificates): X509
    {
        foreach ($trustedCertificates->getCertificates() as $trustedCertificate) {
            $certificate->loadCA(
                $trustedCertificate->saveX509($trustedCertificate->getCurrentCert(), X509::FORMAT_PEM)
            );
        }

        if ($certificate->validateSignature()) {
            $chain = $certificate->getChain();
            return end($chain);
        }

        throw new CertificateNotTrustedException($certificate);
    }

    public static function buildTrustFromCertificates(array $certificates): TrustedCertificates
    {
        return new TrustedCertificates($certificates);
    }
}
