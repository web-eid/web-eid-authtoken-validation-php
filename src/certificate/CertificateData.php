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
use UnexpectedValueException;
use BadFunctionCallException;

final class CertificateData
{

    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    /**
     * Get commonName from x509 certificate
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectCN(X509 $certificate): string
    {
        return self::getField($certificate, 'id-at-commonName');
    }

    /**
     * Get surname from x509 certificate
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectSurname(X509 $certificate): string
    {
        return self::getField($certificate, 'id-at-surname');
    }

    /**
     * Get given name from x509 certificate
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectGivenName(X509 $certificate): string
    {
        return self::getField($certificate, 'id-at-givenName');
    }

    /**
     * Get serialNumber (ID-code) from x509 certificate
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectIdCode(X509 $certificate): string
    {
        return self::getField($certificate, 'id-at-serialNumber');
    }

    /**
     * Get country code from x509 certificate
     *
     * @throws UnexpectedValueException
     */
    public static function getSubjectCountryCode(X509 $certificate): string
    {
        return self::getField($certificate, 'id-at-countryName');
    }

    /**
     * Get specified subject field from x509 certificate
     *
     * @throws UnexpectedValueException field identifier not found
     * @return string
     */
    private static function getField(X509 $certificate, string $fieldId): string
    {
        $result = $certificate->getSubjectDNProp($fieldId);
        if ($result) {
            return $result[0];
        }
        throw new UnexpectedValueException("fieldId " . $fieldId . " not found in certificate subject");
    }
}
