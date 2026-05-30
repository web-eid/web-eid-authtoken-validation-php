<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp\maps;

use phpseclib3\File\ASN1;

/**
 * The map has been created with help from Petr Muzikant project:
 * https://github.com/Muzosh/web-eid-authtoken-validation-php
 */
abstract class OcspResponseMap
{
    public const MAP = [
        "type" => ASN1::TYPE_SEQUENCE,
        "children" => [
            "responseStatus" => [
                "type" => ASN1::TYPE_ENUMERATED,
                "mapping" => [
                    0 => "successful",
                    1 => "malformedRequest",
                    2 => "internalError",
                    3 => "tryLater",
                    5 => "sigRequired",
                    6 => "unauthorized",
                ],
            ],
            "responseBytes" => [
                "constant" => 0,
                "explicit" => true,
                "optional" => true,
                "type" => ASN1::TYPE_SEQUENCE,
                "children" => [
                    "responseType" => ["type" => ASN1::TYPE_OBJECT_IDENTIFIER],
                    "response" => ["type" => ASN1::TYPE_OCTET_STRING],
                ],
            ],
        ],
    ];
}
