<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\certificate;

use phpseclib3\File\X509;
use BadFunctionCallException;

final class CertificateData
{

    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    /**
     * Get commonName from x509 certificate
     */
    public static function getSubjectCN(X509 $certificate): ?string
    {
        return self::getField($certificate, 'id-at-commonName');
    }

    /**
     * Get surname from x509 certificate
     */
    public static function getSubjectSurname(X509 $certificate): ?string
    {
        return self::getField($certificate, 'id-at-surname');
    }

    /**
     * Get given name from x509 certificate
     */
    public static function getSubjectGivenName(X509 $certificate): ?string
    {
        return self::getField($certificate, 'id-at-givenName');
    }

    /**
     * Get serialNumber (ID-code) from x509 certificate
     */
    public static function getSubjectIdCode(X509 $certificate): ?string
    {
        return self::getField($certificate, 'id-at-serialNumber');
    }

    /**
     * Get country code from x509 certificate
     */
    public static function getSubjectCountryCode(X509 $certificate): ?string
    {
        return self::getField($certificate, 'id-at-countryName');
    }

    /**
     * Get specified subject field from x509 certificate
     *
     * @return ?string
     */
    private static function getField(X509 $certificate, string $fieldId): ?string
    {
        $result = $certificate->getSubjectDNProp($fieldId);
        if ($result) {
            return join(", ", $result);
        } else {
            return null;
        }
    }
}
