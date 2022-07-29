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

namespace web_eid\web_eid_authtoken_validation_php\testutil;

use web_eid\web_eid_authtoken_validation_php\certificate\CertificateValidator;
use web_eid\web_eid_authtoken_validation_php\util\Uri;
use web_eid\web_eid_authtoken_validation_php\util\UriCollection;
use web_eid\web_eid_authtoken_validation_php\util\X509Collection;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspServiceProvider;
use web_eid\web_eid_authtoken_validation_php\validator\ocsp\OcspUrl;
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
            new UriCollection(new Uri(OcspUrl::AIA_ESTEID_2015_URL), new Uri(self::TEST_ESTEID_2015)),
            CertificateValidator::buildTrustFromCertificates([Certificates::getTestEsteid2015CA(), Certificates::getTestEsteid2018CA()])
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