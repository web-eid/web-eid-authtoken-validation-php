<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Certificate;
use phpseclib3\File\ASN1\Maps\CertificateSerialNumber;
use phpseclib3\File\ASN1\Maps\Extensions;
use phpseclib3\File\ASN1\Maps\GeneralName;

/**
 * The map has been created with help from Petr Muzikant project:
 * https://github.com/Muzosh/web-eid-authtoken-validation-php
 */
abstract class OcspRequestMap
{
    public const MAP = [
        "type" => ASN1::TYPE_SEQUENCE,
        "children" => [
            "tbsRequest" => [
                "type" => ASN1::TYPE_SEQUENCE,
                "children" => [
                    "version" => [
                        "constant" => 0,
                        "explicit" => true,
                        "optional" => true,
                        "mapping" => [0 => "v1"],
                        "default" => "v1",
                        "type" => ASN1::TYPE_INTEGER,
                    ],
                    "requestList" => [
                        "type" => ASN1::TYPE_SEQUENCE,
                        "min" => 0,
                        "max" => -1,
                        "children" => [
                            "type" => ASN1::TYPE_SEQUENCE,
                            "children" => [
                                "reqCert" => [
                                    "type" => ASN1::TYPE_SEQUENCE,
                                    "children" => [
                                        "hashAlgorithm" =>
                                            AlgorithmIdentifier::MAP,
                                        "issuerNameHash" => [
                                            "type" => ASN1::TYPE_OCTET_STRING,
                                        ],
                                        "issuerKeyHash" => [
                                            "type" => ASN1::TYPE_OCTET_STRING,
                                        ],
                                        "serialNumber" =>
                                            CertificateSerialNumber::MAP,
                                    ],
                                ],
                                "singleRequestExtensions" =>
                                    [
                                        "constant" => 0,
                                        "explicit" => true,
                                        "optional" => true,
                                    ] + Extensions::MAP,
                            ],
                        ],
                    ],
                    "requestExtensions" =>
                        [
                            "constant" => 2,
                            "explicit" => true,
                            "optional" => true,
                        ] + Extensions::MAP,
                    "requestorName" =>
                        [
                            "constant" => 1,
                            "optional" => true,
                            "explicit" => true,
                        ] + GeneralName::MAP,
                ],
            ],
            "optionalSignature" => [
                "constant" => 0,
                "explicit" => true,
                "optional" => true,
                "type" => ASN1::TYPE_SEQUENCE,
                "children" => [
                    "signatureAlgorithm" => AlgorithmIdentifier::MAP,
                    "signature" => ["type" => ASN1::TYPE_BIT_STRING],
                    "certs" => [
                        "constant" => 0,
                        "explicit" => true,
                        "optional" => true,
                        "type" => ASN1::TYPE_SEQUENCE,
                        "min" => 0,
                        "max" => -1,
                        "children" => Certificate::MAP,
                    ],
                ],
            ],
        ],
    ];
}
