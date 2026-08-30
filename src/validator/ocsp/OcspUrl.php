<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;
use phpseclib3\File\X509;
use GuzzleHttp\Psr7\Uri;
use Exception;
use InvalidArgumentException;

final class OcspUrl
{
    public function __construct()
    {
        throw new BadFunctionCallException("Utility class");
    }

    /**
     * Returns the OCSP responder {@link URI} or {@code null} if it doesn't have one.
     * 
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public static function getOcspUri(X509 $certificate): ?Uri
    {
        if (is_null($certificate)) {
            throw new InvalidArgumentException("Certificate must not be null");
        }
        $authorityInformationAccess = $certificate->getExtension("id-pe-authorityInfoAccess");
        if ($authorityInformationAccess) {
            foreach ($authorityInformationAccess as $accessDescription) {
                if (in_array($accessDescription["accessMethod"], ["id-pkix-ocsp", "id-ad-ocsp"]) && array_key_exists("uniformResourceIdentifier", $accessDescription["accessLocation"])) {
                    $accessLocationUrl = $accessDescription["accessLocation"]["uniformResourceIdentifier"];
                    return new Uri($accessLocationUrl);
                }
            }
        }

        return null;
    }
}
