<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Name;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspCertificateException;
use web_eid\web_eid_authtoken_validation_php\util\AsnUtil;
use web_eid\web_eid_authtoken_validation_php\util\HashAlgorithm;

class Ocsp
{
    /**
     * The media type (Content-Type header) to be used when sending the request to the OCSP Responder URL.
     *
     * @var string
     */
    const OCSP_REQUEST_MEDIATYPE = "application/ocsp-request";

    /**
     * The media type (Content-Type header) that should be included in responses from the OCSP Responder URL.
     *
     * @var string
     */
    const OCSP_RESPONSE_MEDIATYPE = "application/ocsp-response";

    /**
     * Response type for a basic OCSP responder
     *
     * @var string
     */
    public const ID_PKIX_OCSP_BASIC_STRING = "id-pkix-ocsp-basic";

    /**
     * Generates certificate ID with subject and issuer certificates
     *
     * @param X509 certificate - subject certificate
     * @param X509 issuerCertificate - issuer certificate
     * @return array
     * @throws OcspCertificateException when the subject or issuer certificates don't have required data
     */
    public function generateCertificateId(
        X509 $certificate,
        X509 $issuerCertificate,
        HashAlgorithm $hashAlgorithm = HashAlgorithm::SHA1
    ): array {
        AsnUtil::loadOIDs();

        $certificateId = [
            "hashAlgorithm" => [],
            "issuerNameHash" => "",
            "issuerKeyHash" => "",
            "serialNumber" => [],
        ];

        if (
            !isset(
                $certificate->getCurrentCert()["tbsCertificate"]["serialNumber"]
            )
        ) {
            // Serial number of subject certificate does not exist
            throw new OcspCertificateException(
                "Serial number of subject certificate does not exist"
            );
        }

        $certificateId["serialNumber"] = clone $certificate->getCurrentCert()["tbsCertificate"]["serialNumber"];

        // issuer name
        if (
            !isset(
                $issuerCertificate->getCurrentCert()["tbsCertificate"][
                    "subject"
                ]
            )
        ) {
            // Serial number of issuer certificate does not exist
            throw new OcspCertificateException(
                "Serial number of issuer certificate does not exist"
            );
        }

        $issuer = $issuerCertificate->getCurrentCert()["tbsCertificate"][
            "subject"
        ];
        $issuerEncoded = ASN1::encodeDER($issuer, Name::MAP);
        $certificateId["issuerNameHash"] = hash($hashAlgorithm->value, $issuerEncoded, true);

        // issuer public key
        if (
            !isset(
                $issuerCertificate->getCurrentCert()["tbsCertificate"][
                    "subjectPublicKeyInfo"
                ]["subjectPublicKey"]
            )
        ) {
            // SubjectPublicKey of issuer certificate does not exist
            throw new OcspCertificateException(
                "SubjectPublicKey of issuer certificate does not exist"
            );
        }

        $publicKey = $issuerCertificate->getCurrentCert()["tbsCertificate"][
            "subjectPublicKeyInfo"
        ]["subjectPublicKey"];
        $certificateId["issuerKeyHash"] = hash(
            $hashAlgorithm->value,
            AsnUtil::extractKeyData($publicKey),
            true
        );

        $certificateId["hashAlgorithm"]["algorithm"] = Asn1::getOID("id-" . $hashAlgorithm->value);

        return $certificateId;
    }
}
