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

namespace web_eid\web_eid_authtoken_validation_php\validator\ocsp;

use BadFunctionCallException;
use phpseclib3\File\X509;
use GuzzleHttp\Psr7\Uri;
use Exception;

final class OcspUrl
{
    public const AIA_ESTEID_2015_URL = "http://aia.sk.ee/esteid2015";

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
