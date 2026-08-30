<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\ocsp\certificate;

use PHPUnit\Framework\TestCase;
use web_eid\web_eid_authtoken_validation_php\ocsp\exceptions\OcspCertificateException;
use web_eid\web_eid_authtoken_validation_php\util\AsnUtil;

class CertificateLoaderTest extends TestCase
{
    public function testWhenCertificateLoaderFromFileSuccess(): void
    {
        $loader = (new CertificateLoader)->fromFile(__DIR__.'/../../_resources/revoked.crt');

        $this->assertEquals("318601422914101149693420017798940712227677", $loader->getCert()->getCurrentCert()['tbsCertificate']['serialNumber']);
        $this->assertEquals("http://cert.int-x3.letsencrypt.org/", $loader->getIssuerCertificateUrl());
        $this->assertEquals("http://ocsp.int-x3.letsencrypt.org", $loader->getOcspResponderUrl());
    }

    public function testWhenCertificateLoaderFromStringSuccess(): void
    {
        $certData = file_get_contents(__DIR__.'/../../_resources/revoked.crt');
        $certificate = (new CertificateLoader)->fromString($certData)->getCert();
        $this->assertEquals("318601422914101149693420017798940712227677", $certificate->getCurrentCert()['tbsCertificate']['serialNumber']);
    }

    public function testWhenCertificateFileDoNotExistThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Certificate file not found or not readable: '.__DIR__.'/../../_resources/somecert.crt');

        (new CertificateLoader)->fromFile(__DIR__.'/../../_resources/somecert.crt');

    }

    public function testWhenCertificateIsInvalidThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Certificate decoding from Base64 or parsing failed for '.__DIR__.'/../../_resources/invalid.crt');

        (new CertificateLoader)->fromFile(__DIR__.'/../../_resources/invalid.crt');
    }

    public function testWhenCertificateStringIsNotValidThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Certificate decoding from Base64 or parsing failed');

        (new CertificateLoader)->fromString("certsource");
    }

    public function testWhenCertificateIsNotLoadedOnIssuerCertificateUrlThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Certificate not loaded');

        (new CertificateLoader)->getIssuerCertificateUrl();
    }

    public function testWhenCertificateIsNotLoadedOnOcspResponderUrlThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Certificate not loaded');

        (new CertificateLoader)->getOcspResponderUrl();
    }

    public function testWhenCertificateIsNotLoadedOnGetCertThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Certificate not loaded');

        (new CertificateLoader)->getCert();
    }

}
