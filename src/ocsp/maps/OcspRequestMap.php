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
