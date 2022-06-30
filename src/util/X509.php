<?php

/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

namespace web_eid\web_eid_authtoken_validation_php\util;

use DateTimeImmutable;
use OpenSSLAsymmetricKey;
use Exception;

final class X509
{
    private $certificate = null;
    private OpenSSLAsymmetricKey $publicKey;

    public function loadX509(string $cert)
    {
        if (!str_contains($cert, "-----BEGIN CERTIFICATE-----") || !str_contains($cert, "-----END CERTIFICATE-----")) {
            $cert = $this->derToPem($cert);
        }

        $x509Res = openssl_x509_read($cert);
        if ($x509Res === FALSE) {
            return null;
        }

        $this->publicKey = openssl_pkey_get_public($cert);
        if ($this->publicKey == 0)
        {
            return null;
        }
        elseif ($this->publicKey == false)
        {
            return null;
        }
        
        $this->certificate = $cert;
        return $this;
        
    }

    public function getSubjectProp(string $fieldIdentifier): mixed
    {
        if (!$this->certificate) {
            return null;
        }
        $parsedCertificate = openssl_x509_parse($this->certificate);
        if (isset($parsedCertificate['subject'][$fieldIdentifier])) {
            return $parsedCertificate['subject'][$fieldIdentifier];
        } 
        return null;
    }

    private function getNotBefore(): mixed
    {
        if (!$this->certificate) {
            return null;
        }
        $parsedCertificate = openssl_x509_parse($this->certificate);
        if (isset($parsedCertificate['validFrom_time_t'])) {
            return new DateTimeImmutable(date(DATE_RFC2822, $parsedCertificate['validFrom_time_t']));
        } 
        return null;
    }

    private function getNotAfter(): mixed
    {
        if (!$this->certificate) {
            return null;
        }
        $parsedCertificate = openssl_x509_parse($this->certificate);
        if (isset($parsedCertificate['validTo_time_t'])) {
            return new DateTimeImmutable(date(DATE_RFC2822, $parsedCertificate['validTo_time_t']));
        } 
        return null;
    }

    public function checkValidity($date = null): void
    {
        if (!$this->certificate) {
            throw new Exception("Missing certificate", 0);
        }

        if (!isset($date)) {
            $date = new DateTimeImmutable('now');
        }

        if (is_string($date)) {
            $date = new DateTimeImmutable($date);
        }

        $notBefore = $this->getNotBefore();
        $notAfter = $this->getNotAfter();

        if (!$notBefore || !$notAfter) {
            throw new Exception("Missing validTo or notValidBefore fields", 0);
        }

        if ($date < $notBefore) {
            throw new Exception("Certificate is not valid yet", 1);
        }

        if ($date > $notAfter) {
            throw new Exception("Certificate has expired", 2);
        }
    }

    public function getExtendedKeyUsage()
    {
        if (!$this->certificate) {
            return null;
        }
        $parsedCertificate = openssl_x509_parse($this->certificate);
        if (!isset($parsedCertificate['extensions']['extendedKeyUsage'])) {
            return null;
        }
        return explode(', ', $parsedCertificate['extensions']['extendedKeyUsage']);
    }

    public function getExdendedCertificatePolicies()
    {
        if (!$this->certificate) {
            return null;
        }
        $parsedCertificate = openssl_x509_parse($this->certificate);
        if (!isset($parsedCertificate['extensions']['certificatePolicies'])) {
            return null;
        }
        return $parsedCertificate['extensions']['certificatePolicies'];
    }

    public function loadCA($cert)
    {

    }

    private function derToPem(string $derData): string
    {
        $certDER = base64_decode($derData);
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($certDER), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    private function pemToDer(string $pemData): string
    {
        $begin = "CERTIFICATE-----";
        $end   = "-----END";        
        $pem_data = substr($pemData, strpos($pemData, $begin)+strlen($begin));   
        $pem_data = substr($pemData, 0, strpos($pemData, $end));
        $der = base64_decode($pem_data);
        return $der;
    }

}