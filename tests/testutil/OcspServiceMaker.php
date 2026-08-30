<?php

// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

namespace web_eid\web_eid_authtoken_validation_php\testutil;

use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use GuzzleHttp\Psr7\Uri;
use web_eid\web_eid_authtoken_validation_php\util\UriCollection;
use web_eid\web_eid_authtoken_validation_php\util\X509Collection;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\AiaOcspServiceConfiguration;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\service\DesignatedOcspServiceConfiguration;

class OcspServiceMaker
{

    private const TEST_OCSP_ACCESS_LOCATION = "http://demo.sk.ee/ocsp";
    private const TEST_ESTEID_2015 = "http://aia.demo.sk.ee/esteid2015";

    public static function getAiaOcspServiceProvider(): OcspServiceProvider
    {
        return new OcspServiceProvider(null, self::getAiaOcspServiceConfiguration());
    }

    public static function getDesignatedOcspServiceProvider(bool $doesSupportNonce = true, string $ocspServiceAccessLocation = self::TEST_OCSP_ACCESS_LOCATION): OcspServiceProvider
    {
        return new OcspServiceProvider(self::getDesignatedOcspServiceConfiguration($doesSupportNonce, $ocspServiceAccessLocation), self::getAiaOcspServiceConfiguration());
    }

    private static function getAiaOcspServiceConfiguration(): AiaOcspServiceConfiguration
    {
        return new AiaOcspServiceConfiguration(
            new UriCollection(new Uri(self::TEST_ESTEID_2015)),
            CertificateValidator::buildTrustFromCertificates([Certificates::getTestEsteid2018CA(), Certificates::getTestEsteid2018CAGov()])
        );
    }

    public static function getDesignatedOcspServiceConfiguration(bool $doesSupportNonce = true, string $ocspServiceAccessLocation = self::TEST_OCSP_ACCESS_LOCATION): DesignatedOcspServiceConfiguration
    {
        return new DesignatedOcspServiceConfiguration(
            new Uri($ocspServiceAccessLocation),
            Certificates::getTestSkOcspResponder2020(),
            new X509Collection(Certificates::getTestEsteid2018CA(), Certificates::getTestEsteid2015CA()),
            $doesSupportNonce
        );
    }
}
