<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\certificate;

use web_eid\web_eid_authtoken_validation_php\exceptions\CertificateDecodingException;
use phpseclib3\File\X509;
use BadFunctionCallException;

final class CertificateLoader
{

    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    /**
     * Loads certificate files from paths into array of OpenSSLCertificate
     * @param string ...$resourceNames array of certificate paths
     * 
     * @return array
     * @throws CertificateDecodingException
     */
    public static function loadCertificatesFromResources(string ...$resourceNames): array
    {
        $caCertificates = [];
        foreach ($resourceNames as $resourceName) {
            $cert = new X509();
            $loaded = $cert->loadX509(file_get_contents($resourceName));
            if ($loaded) {
                array_push($caCertificates, $cert);
            } else {
                throw new CertificateDecodingException($resourceName);
            }
        }
        return $caCertificates;
    }
}
