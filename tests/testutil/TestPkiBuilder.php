<?php

/*
 * Copyright (c) 2026 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\testutil;

use DateTime;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Certificate;
use phpseclib3\File\X509;
use RuntimeException;
use web_eid\web_eid_authtoken_validation_php\ocsp\maps\OcspBasicResponseMap;
use web_eid\web_eid_authtoken_validation_php\ocsp\maps\OcspResponseMap;
use web_eid\web_eid_authtoken_validation_php\util\AsnUtil;

/**
 * Generates a synthetic test PKI: root and intermediate CA certificates, leaf certificates,
 * OCSP responder certificates, cross- and impostor certificates, CRLs and OCSP responses.
 *
 * EC nistP256 keys are used for speed. All produced certificates are saved to PEM and
 * reloaded before being returned, because phpseclib verifies signatures against the
 * certificate bytes captured at load time.
 *
 * Supported entries of the $options array accepted by the build methods:
 * - "notBefore" (DateTime): validity start, default one day in the past
 * - "notAfter" (DateTime): validity end, default one year in the future
 * - "aiaOcspUrl" (string): adds an Authority Information Access extension with an
 *   OCSP responder access description
 * - "crlDistributionPointUrl" (string): adds a CRL Distribution Points extension
 * - "extendedKeyUsage" (string[]): adds an Extended Key Usage extension, e.g.
 *   ["id-kp-OCSPSigning"]
 * - "keyPair" (PrivateKey): reuses the given key pair instead of generating a new one
 */
final class TestPkiBuilder
{
    private int $nextSerialNumber = 1000;

    public function buildRootCa(string $commonName, array $options = []): TestPkiCredential
    {
        return $this->issueCertificate($commonName, null, true, $options);
    }

    public function buildIntermediateCa(
        string $commonName,
        TestPkiCredential $issuer,
        array $options = [],
    ): TestPkiCredential {
        return $this->issueCertificate($commonName, $issuer, true, $options);
    }

    public function buildLeaf(
        string $commonName,
        TestPkiCredential $issuer,
        array $options = [],
    ): TestPkiCredential {
        return $this->issueCertificate($commonName, $issuer, false, $options);
    }

    public function buildOcspResponder(
        string $commonName,
        TestPkiCredential $issuer,
        bool $withOcspSigningExtendedKeyUsage = true,
        array $options = [],
    ): TestPkiCredential {
        if ($withOcspSigningExtendedKeyUsage) {
            $options["extendedKeyUsage"] = ["id-kp-OCSPSigning"];
        }
        return $this->issueCertificate($commonName, $issuer, false, $options);
    }

    /**
     * Builds a cross-certificate: same subject DN and same public key as the original
     * certificate, but a different serial number and a different issuer.
     */
    public function buildCrossCertificate(
        TestPkiCredential $original,
        TestPkiCredential $newIssuer,
        array $options = [],
    ): TestPkiCredential {
        $options["keyPair"] = $original->getPrivateKey();
        return $this->issueCertificate(
            self::getCommonName($original),
            $newIssuer,
            true,
            $options,
        );
    }

    /**
     * Builds an impostor CA certificate: same subject DN as the original certificate,
     * but a newly generated, different key pair.
     */
    public function buildImpostorCa(
        TestPkiCredential $original,
        TestPkiCredential $issuer,
        array $options = [],
    ): TestPkiCredential {
        return $this->issueCertificate(
            self::getCommonName($original),
            $issuer,
            true,
            $options,
        );
    }

    /**
     * Builds a CRL signed by the given CA that revokes the given serial numbers.
     *
     * @param string[] $revokedSerialNumbers decimal serial number strings
     * @param bool $includeNextUpdate whether the CRL contains a nextUpdate field
     * @return string the CRL in PEM format
     */
    public function buildCrl(
        TestPkiCredential $issuerCa,
        array $revokedSerialNumbers,
        ?DateTime $thisUpdate = null,
        ?DateTime $nextUpdate = null,
        bool $includeNextUpdate = true,
    ): string {
        $authority = $this->toSigningAuthority($issuerCa);

        // Sign an empty CRL first; X509::revoke() requires an already loaded CRL.
        $signer = new X509();
        $signer->setStartDate($thisUpdate ?? new DateTime("-1 hour"));
        if ($includeNextUpdate) {
            $signer->setEndDate($nextUpdate ?? new DateTime("+1 day"));
        }
        $signed = $signer->signCRL($authority, new X509());
        if ($signed === false) {
            throw new RuntimeException("Signing the test CRL failed");
        }

        if ($revokedSerialNumbers === []) {
            return $signer->saveCRL($signed);
        }

        $crl = new X509();
        $crl->loadCRL($signer->saveCRL($signed));
        foreach ($revokedSerialNumbers as $serialNumber) {
            if (!$crl->revoke($serialNumber)) {
                throw new RuntimeException("Revoking serial " . $serialNumber . " in the test CRL failed");
            }
        }

        $resigner = new X509();
        $resigner->setStartDate($thisUpdate ?? new DateTime("-1 hour"));
        if ($includeNextUpdate) {
            $resigner->setEndDate($nextUpdate ?? new DateTime("+1 day"));
        }
        $resigned = $resigner->signCRL($authority, $crl);
        if ($resigned === false) {
            throw new RuntimeException("Re-signing the test CRL failed");
        }
        return $resigner->saveCRL($resigned);
    }

    /**
     * Builds a DER-encoded OCSP response for the given certificate ID, signed by the
     * given responder.
     *
     * @param array $certificateId a CertID structure as produced by Ocsp::generateCertificateId()
     * @param string|array $certStatus "good", "unknown" or ["revoked" => ["revokedTime" => ...]];
     *        the string "revoked" produces a revocation at the current time
     */
    public function buildOcspResponseDer(
        array $certificateId,
        TestPkiCredential $responder,
        string|array $certStatus = "good",
        ?DateTime $producedAt = null,
        ?DateTime $thisUpdate = null,
        ?DateTime $nextUpdate = null,
    ): string {
        AsnUtil::loadOIDs();

        if ($certStatus === "good") {
            $certStatus = ["good" => ""];
        } elseif ($certStatus === "unknown") {
            $certStatus = ["unknown" => ""];
        } elseif ($certStatus === "revoked") {
            $certStatus = ["revoked" => ["revokedTime" => self::toAsnTime(new DateTime("-1 hour"))]];
        }

        $responderCertificateArray = self::toRawCertificateArray($responder->getCertificatePem());

        $singleResponse = [
            "certID" => $certificateId,
            "certStatus" => $certStatus,
            "thisUpdate" => self::toAsnTime($thisUpdate ?? new DateTime("-1 minute")),
        ];
        if ($nextUpdate !== null) {
            $singleResponse["nextUpdate"] = self::toAsnTime($nextUpdate);
        }

        $tbsResponseData = [
            "responderID" => [
                "byName" => $responderCertificateArray["tbsCertificate"]["subject"],
            ],
            "producedAt" => self::toAsnTime($producedAt ?? new DateTime()),
            "responses" => [$singleResponse],
        ];

        $tbsResponseDataDer = ASN1::encodeDER(
            $tbsResponseData,
            OcspBasicResponseMap::MAP["children"]["tbsResponseData"]
        );

        $signature = $responder->getPrivateKey()->sign($tbsResponseDataDer);

        $basicResponse = [
            "tbsResponseData" => $tbsResponseData,
            "signatureAlgorithm" => ["algorithm" => "ecdsa-with-SHA256"],
            // The first octet of a BIT STRING value is the unused bits count.
            "signature" => "\0" . $signature,
            "certs" => [$responderCertificateArray],
        ];
        $basicResponseDer = ASN1::encodeDER($basicResponse, OcspBasicResponseMap::MAP);

        return ASN1::encodeDER(
            [
                "responseStatus" => "successful",
                "responseBytes" => [
                    "responseType" => "id-pkix-ocsp-basic",
                    "response" => $basicResponseDer,
                ],
            ],
            OcspResponseMap::MAP
        );
    }

    private function issueCertificate(
        string $commonName,
        ?TestPkiCredential $issuer,
        bool $isCa,
        array $options,
    ): TestPkiCredential {
        $keyPair = $options["keyPair"] ?? EC::createKey("nistP256");
        $publicKey = $keyPair->getPublicKey();

        $subject = new X509();
        $subject->setDN(["id-at-commonName" => $commonName]);
        $subject->setPublicKey($publicKey);
        // computeKeyIdentifier() does not accept public key objects, so pass PEM.
        $subject->setKeyIdentifier($subject->computeKeyIdentifier($publicKey->toString("PKCS8")));

        $authority = $issuer === null
            ? $this->toSelfSigningAuthority($commonName, $keyPair, $subject)
            : $this->toSigningAuthority($issuer);

        $signer = new X509();
        if ($isCa) {
            // Adds cA=true basicConstraints and keyCertSign+cRLSign keyUsage during signing.
            $signer->makeCA();
        } else {
            $signer->setExtensionValue("id-ce-keyUsage", ["digitalSignature"]);
        }
        $signer->setStartDate($options["notBefore"] ?? new DateTime("-1 day"));
        $signer->setEndDate($options["notAfter"] ?? new DateTime("+1 year"));
        $signer->setSerialNumber((string) $this->nextSerialNumber++, 10);

        if (isset($options["aiaOcspUrl"])) {
            $signer->setExtensionValue("id-pe-authorityInfoAccess", [
                [
                    "accessMethod" => "id-ad-ocsp",
                    "accessLocation" => ["uniformResourceIdentifier" => $options["aiaOcspUrl"]],
                ],
            ]);
        }
        if (isset($options["crlDistributionPointUrl"])) {
            $signer->setExtensionValue("id-ce-cRLDistributionPoints", [
                [
                    "distributionPoint" => [
                        "fullName" => [
                            ["uniformResourceIdentifier" => $options["crlDistributionPointUrl"]],
                        ],
                    ],
                ],
            ]);
        }
        if (isset($options["extendedKeyUsage"])) {
            $signer->setExtensionValue("id-ce-extKeyUsage", $options["extendedKeyUsage"]);
        }

        $issued = $signer->sign($authority, $subject);
        if ($issued === false) {
            throw new RuntimeException("Signing the test certificate " . $commonName . " failed");
        }

        // Save to PEM; TestPkiCredential always reloads it into a fresh X509 object so that
        // signatureSubject is captured from the actual certificate bytes.
        return new TestPkiCredential($signer->saveX509($issued), $keyPair);
    }

    private function toSigningAuthority(TestPkiCredential $issuer): X509
    {
        // Loading the certificate sets the issuing DN and the current key identifier
        // (used for the authority key identifier extension) from the certificate.
        $authority = $issuer->getCertificate();
        $authority->setPrivateKey($issuer->getPrivateKey());
        return $authority;
    }

    private function toSelfSigningAuthority(string $commonName, PrivateKey $keyPair, X509 $subject): X509
    {
        $authority = new X509();
        $authority->setDN(["id-at-commonName" => $commonName]);
        $authority->setPrivateKey($keyPair);
        $authority->setKeyIdentifier(
            $subject->computeKeyIdentifier($keyPair->getPublicKey()->toString("PKCS8"))
        );
        return $authority;
    }

    private static function getCommonName(TestPkiCredential $credential): string
    {
        $commonName = $credential->getCertificate()->getSubjectDNProp("id-at-commonName");
        if (!is_array($commonName) || !isset($commonName[0])) {
            throw new RuntimeException("The certificate does not have a common name");
        }
        return $commonName[0];
    }

    /**
     * Parses a certificate into the raw ASN.1-mapped array form that the OCSP basic
     * response "certs" field uses (extension values remain unmapped octet strings).
     */
    private static function toRawCertificateArray(string $certificatePem): array
    {
        $der = ASN1::extractBER($certificatePem);
        $decoded = ASN1::decodeBER($der);
        $certificate = ASN1::asn1map($decoded[0], Certificate::MAP);
        if (!is_array($certificate)) {
            throw new RuntimeException("Decoding the test certificate failed");
        }
        return $certificate;
    }

    private static function toAsnTime(DateTime $dateTime): string
    {
        return $dateTime->format("D, d M Y H:i:s O");
    }
}
