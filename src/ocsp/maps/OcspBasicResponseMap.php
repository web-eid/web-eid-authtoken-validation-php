<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp\maps;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\AlgorithmIdentifier;
use phpseclib3\File\ASN1\Maps\Certificate;
use phpseclib3\File\ASN1\Maps\CertificateSerialNumber;
use phpseclib3\File\ASN1\Maps\CRLReason;
use phpseclib3\File\ASN1\Maps\Extensions;
use phpseclib3\File\ASN1\Maps\Name;

/**
 * The map has been created with help from Petr Muzikant project:
 * https://github.com/Muzosh/web-eid-authtoken-validation-php
 */
abstract class OcspBasicResponseMap
{
    public const MAP = [
        "type" => ASN1::TYPE_SEQUENCE,
        "children" => [
            "tbsResponseData" => [
                "type" => ASN1::TYPE_SEQUENCE,
                "children" => [
                    "version" => [
                        "type" => ASN1::TYPE_INTEGER,
                        "constant" => 0,
                        "optional" => true,
                        "explicit" => true,
                        "mapping" => ["v1"],
                        "default" => "v1",
                    ],
                    "responderID" => [
                        "type" => ASN1::TYPE_CHOICE,
                        "children" => [
                            "byName" =>
                                [
                                    "constant" => 1,
                                    "explicit" => true,
                                ] + Name::MAP,
                            "byKey" => [
                                "constant" => 2,
                                "explicit" => true,
                                "type" => ASN1::TYPE_OCTET_STRING,
                            ],
                        ],
                    ],
                    "producedAt" => ["type" => ASN1::TYPE_GENERALIZED_TIME],
                    "responses" => [
                        "type" => ASN1::TYPE_SEQUENCE,
                        "min" => 0,
                        "max" => -1,
                        "children" => [
                            "type" => ASN1::TYPE_SEQUENCE,
                            "children" => [
                                "certID" => [
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
                                "certStatus" => [
                                    "type" => ASN1::TYPE_CHOICE,
                                    "children" => [
                                        "good" => [
                                            "constant" => 0,
                                            "implicit" => true,
                                            "type" => ASN1::TYPE_NULL,
                                        ],
                                        "revoked" => [
                                            "constant" => 1,
                                            "implicit" => true,
                                            "type" => ASN1::TYPE_SEQUENCE,
                                            "children" => [
                                                "revokedTime" => [
                                                    "type" =>
                                                        ASN1::TYPE_GENERALIZED_TIME,
                                                ],
                                                "revokedReason" =>
                                                    [
                                                        "constant" => 0,
                                                        "explicit" => true,
                                                        "optional" => true,
                                                    ] + CRLReason::MAP,
                                            ],
                                        ],
                                        "unknown" => [
                                            "constant" => 2,
                                            "implicit" => true,
                                            "type" => ASN1::TYPE_NULL,
                                        ],
                                    ],
                                ],
                                "thisUpdate" => [
                                    "type" => ASN1::TYPE_GENERALIZED_TIME,
                                ],
                                "nextUpdate" => [
                                    "type" => ASN1::TYPE_GENERALIZED_TIME,
                                    "constant" => 0,
                                    "explicit" => true,
                                    "optional" => true,
                                ],
                                "singleExtensions" =>
                                    [
                                        "constant" => 1,
                                        "explicit" => true,
                                        "optional" => true,
                                    ] + Extensions::MAP,
                            ],
                        ],
                    ],
                    "responseExtensions" =>
                        [
                            "constant" => 1,
                            "explicit" => true,
                            "optional" => true,
                        ] + Extensions::MAP,
                ],
            ],
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
    ];
}
