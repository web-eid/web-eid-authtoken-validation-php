<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

declare(strict_types=1);

namespace web_eid\web_eid_authtoken_validation_php\ocsp\certificate;

use Exception;
use phpseclib3\File\X509;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspCertificateException;

class CertificateLoader
{
    private ?X509 $certificate = null;

    /**
     * Loads the certificate from file path and returns the certificate
     *
     * @param string pathToFile - full path to the certificate file
     * @throws OcspCertificateException when the certificate decoding or parse fails
     */
    public function fromFile(string $pathToFile)
    {
        if (!is_readable($pathToFile)) {
            throw new OcspCertificateException("Certificate file not found or not readable: " . $pathToFile);
        }
        $fileContent = file_get_contents($pathToFile);
        if ($fileContent === false) {
            throw new OcspCertificateException("Failed to read certificate file: " . $pathToFile);
        }

        $certificate = new X509();
        $loaded = $certificate->loadX509($fileContent);
        if (!$loaded) {
            throw new OcspCertificateException(
                "Certificate decoding from Base64 or parsing failed for " .
                    $pathToFile
            );
        }
        $this->certificate = $certificate;
        return $this;
    }

    /**
     * Loads the certificate from string and returns the certificate
     *
     * @param string certString - certificate as string
     * @throws OcspCertificateException when the certificate decoding or parse fails
     */
    public function fromString(string $certString)
    {
        $certificate = new X509();
        $loaded = false;
        try {
            $loaded = $certificate->loadX509($certString);
        } catch (Exception $e) {
        }
        if (!$loaded) {
            throw new OcspCertificateException(
                "Certificate decoding from Base64 or parsing failed"
            );
        }
        $this->certificate = $certificate;
        return $this;
    }

    public function getIssuerCertificateUrl(): string
    {
        if (!$this->certificate) {
            throw new OcspCertificateException("Certificate not loaded");
        }

        $url = "";
        $opts = $this->certificate->getExtension("id-pe-authorityInfoAccess");
        foreach ($opts as $opt) {
            if ($opt["accessMethod"] == "id-ad-caIssuers") {
                $url = $opt["accessLocation"]["uniformResourceIdentifier"];
                break;
            }
        }
        return $url;
    }

    public function getOcspResponderUrl(): string
    {
        if (!$this->certificate) {
            throw new OcspCertificateException("Certificate not loaded");
        }

        $url = "";
        $opts = $this->certificate->getExtension("id-pe-authorityInfoAccess");
        foreach ($opts as $opt) {
            if ($opt["accessMethod"] == "id-ad-ocsp" || $opt["accessMethod"] == "id-pkix-ocsp") {
                $url = $opt["accessLocation"]["uniformResourceIdentifier"];
                break;
            }
        }
        return $url;
    }

    public function getCert(): X509
    {
        if (!$this->certificate) {
            throw new OcspCertificateException("Certificate not loaded");
        }
        return $this->certificate;
    }
}
