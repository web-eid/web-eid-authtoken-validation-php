<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp;

use phpseclib3\File\ASN1;
use web_eid\web_eid_authtoken_validation_php\ocsp\maps\OcspRequestMap;
use web_eid\web_eid_authtoken_validation_php\util\AsnUtil;

class OcspRequest
{
    private array $ocspRequest;

    public function __construct()
    {
        AsnUtil::loadOIDs();

        $this->ocspRequest = [
            "tbsRequest" => [
                "version" => "v1",
            ],
        ];
    }

    public function addCertificateId(array $certificateId): void
    {
        $request = [
            "reqCert" => $certificateId,
        ];
        $this->ocspRequest["tbsRequest"]["requestList"][] = $request;
    }

    public function addNonceExtension(string $nonce): void
    {
        $nonceExtension = [
            "extnId" => AsnUtil::ID_PKIX_OCSP_NONCE,
            "critical" => false,
            "extnValue" => ASN1::encodeDER($nonce, ['type' => ASN1::TYPE_OCTET_STRING]),
        ];
        $this->ocspRequest["tbsRequest"]["requestExtensions"][] = $nonceExtension;
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public function getNonceExtension(): ?string
    {
        return AsnUtil::decodeNonceExtension($this->ocspRequest["tbsRequest"]["requestExtensions"] ?? []);
    }

    public function getEncodeDer(): string
    {
        return ASN1::encodeDER($this->ocspRequest, OcspRequestMap::MAP);
    }
}
